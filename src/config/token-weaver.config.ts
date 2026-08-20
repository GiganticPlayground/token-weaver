import { existsSync, readFileSync } from 'fs';
import { extname } from 'path';

import YAML from 'yaml';
import { z } from 'zod';

import { config as env } from './index';
import { DEFAULT_ENCRYPTED_CLAIM, parseEncryptionKey } from '../auth/encrypted-claims';
import { HttpError } from '../utils/http-error';

const scalarStringSchema: z.ZodType<string> = z
  .union([z.string(), z.number(), z.boolean()])
  .transform((value) => String(value));

const mappingValueSchema: z.ZodType<unknown> = z.lazy(() =>
  z.union([
    z.string(),
    z.number(),
    z.boolean(),
    z.null(),
    z.array(z.string()),
    z.array(z.number()),
    z.array(z.boolean()),
    z.record(z.string(), mappingValueSchema),
  ]),
);

const mappingObjectSchema = z.record(z.string(), mappingValueSchema);

const errorMappingSchema = z.object({
  condition: z.string().min(1).optional(),
  status: z.number().int().min(400).max(599),
  message: z.string().min(1),
  code: z.string().optional(),
});

const logConfigSchema = z.object({
  request_body: z.boolean().optional().default(false),
  response_body: z.boolean().optional().default(false),
  request_headers: z.boolean().optional().default(false),
}).optional();

const inboundAuthSchema = z
  .object({
    type: z.enum(['bearer', 'api_key', 'none']),
    header: z.string().optional(),
    key: z.string().optional(),
    token: z.string().optional(),
  })
  .superRefine((value, ctx) => {
    if (value.type === 'api_key' && !value.key) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'inbound_auth.key is required when inbound_auth.type is api_key',
        path: ['key'],
      });
    }

    if (value.type === 'bearer' && !value.token) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'inbound_auth.token is required when inbound_auth.type is bearer',
        path: ['token'],
      });
    }
  });

/** Claims the signer sets itself — an encrypted blob cannot occupy one of these. */
const RESERVED_CLAIM_NAMES = new Set(['iss', 'iat', 'exp', 'sub']);

/**
 * Optional block of claims encrypted into a single opaque JWT claim, readable only by holders of
 * the shared secret. Mapped exactly like public `claims`, so `$` path expressions work the same.
 */
const encryptedClaimsSchema = z
  .object({
    secret: z.string().min(1),
    claim: z.string().min(1).optional().default(DEFAULT_ENCRYPTED_CLAIM),
    kid: z.string().min(1).optional(),
    claims: mappingObjectSchema,
  })
  .superRefine((value, ctx) => {
    try {
      parseEncryptionKey(value.secret, 'encrypted_claims.secret');
    } catch (error) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: error instanceof Error ? error.message : 'invalid encrypted_claims.secret',
        path: ['secret'],
      });
    }

    if (RESERVED_CLAIM_NAMES.has(value.claim)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `encrypted_claims.claim cannot be a reserved claim: ${value.claim}`,
        path: ['claim'],
      });
    }

    if (Object.keys(value.claims).length === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'encrypted_claims.claims must not be empty',
        path: ['claims'],
      });
    }
  });

const sharedJwtSchema = z
  .object({
    algorithm: z.enum(['RS256', 'HS256']).optional().default('RS256'),
    secret: z.string().min(1).optional(),
    issuer: z.string().min(1),
    ttl: z.number().int().positive(),
  })
  .superRefine((value, ctx) => {
    if (value.algorithm === 'HS256' && !value.secret) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'jwt.secret is required when algorithm is HS256',
        path: ['secret'],
      });
    }
  });

const directStrategySchema = z.object({
  name: z.string().min(1),
  type: z.literal('direct'),
  inbound_auth: inboundAuthSchema.optional(),
  credential_path: z.string().optional().default('$.request.body.secret'),
  credentials: z
    .array(
      z.object({
        secret: z.string().min(1),
        claims: mappingObjectSchema,
      }),
    )
    .min(1),
  encrypted_claims: encryptedClaimsSchema.optional(),
  jwt: sharedJwtSchema,
});

/**
 * Token exchange: verify a JWT minted by somebody else, then issue ours from its claims.
 *
 * The point is to keep control of what OUR token says. A consumer trusts one issuer (this
 * service) and one claim vocabulary, while upstream identity providers come and go behind it -
 * their claims are mapped here rather than taught to every consumer.
 *
 * Verification reuses the same JWKS path as the exported auth module, so there is one
 * implementation of signature checking in this repo.
 */
const jwtStrategySchema = z.object({
  name: z.string().min(1),
  type: z.literal('jwt'),
  inbound_auth: inboundAuthSchema.optional(),
  /** Where the inbound token is. Default: the Authorization header, 'Bearer ' tolerated. */
  credential_path: z.string().optional().default('$.request.headers.authorization'),
  verify: z.object({
    jwks_uri: z.string().min(1),
    issuer: z.string().min(1),
    audience: z.string().min(1).optional(),
    /** Claims the inbound token must carry, e.g. a scope that authorizes the exchange. */
    requirements: z
      .array(
        z.union([
          z.object({ type: z.literal('scope'), value: z.string().min(1) }),
          z.object({
            type: z.literal('claim_includes'),
            claim: z.string().min(1),
            value: z.string().min(1),
          }),
        ]),
      )
      .optional(),
  }),
  /**
   * Base claims for every client, mapped like any other strategy; the verified payload is at
   * $.request.jwt. A matched `clients` entry's claims are layered over these.
   */
  claims: mappingObjectSchema,
  /**
   * Optional per-client claim sets, so ONE endpoint can issue different tokens depending on
   * which client is calling (a kiosk build, a mobile app) instead of needing a strategy - and
   * therefore a URL - per client.
   *
   * A matched entry's claims are merged over `claims` PER TOP-LEVEL CLAIM: a client that maps
   * `routes` replaces the base `routes` wholesale rather than being deep-merged into it, so a
   * client's permissions read exactly as written instead of depending on what the base said.
   */
  clients: z
    .array(
      z.object({
        client_id: z.string().min(1),
        claims: mappingObjectSchema,
      }),
    )
    .min(1)
    .optional(),
  /** Where the client identifier is read from. Only used when `clients` is set. */
  client_id_path: z.string().optional().default('$.request.body.clientId'),
  /**
   * Whether an unrecognized (or absent) client identifier is rejected. Default TRUE: the client
   * selects which claims it gets, so an unknown one silently falling back to the base claims
   * would be a quiet grant. Set false only when the base claims are a deliberate public tier.
   */
  require_known_client: z.boolean().optional().default(true),
  /**
   * Optional hardening, and the recommended way to run this in production: the name of a
   * VERIFIED claim on the inbound token that must agree with the supplied client identifier
   * (equal, or containing it when the claim is an array).
   *
   * Without it the caller picks its own claim set by sending an identifier, so the identifier is
   * only as strong as its secrecy. With it the upstream token authorizes the client and the
   * identifier merely selects among sets the token already permits.
   */
  client_claim: z.string().min(1).optional(),
  encrypted_claims: encryptedClaimsSchema.optional(),
  jwt: sharedJwtSchema,
});

const upstreamAuthSchema = z
  .object({
    type: z.enum(['bearer', 'api_key', 'none']),
    token: z.string().optional(),
    key: z.string().optional(),
    header: z.string().optional(),
  })
  .superRefine((value, ctx) => {
    if (value.type === 'api_key' && !value.key) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'upstream.auth.key is required when upstream.auth.type is api_key',
        path: ['key'],
      });
    }

    if (value.type === 'bearer' && !value.token) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'upstream.auth.token is required when upstream.auth.type is bearer',
        path: ['token'],
      });
    }
  });

const delegatedStrategySchema = z.object({
  name: z.string().min(1),
  type: z.literal('delegated'),
  inbound_auth: inboundAuthSchema.optional(),
  upstream: z.object({
    url: z.string().min(1),
    method: z
      .string()
      .min(1)
      .transform((method) => method.toUpperCase()),
    timeout_ms: z.number().int().positive().optional(),
    auth: upstreamAuthSchema.optional(),
    headers: z.record(z.string(), scalarStringSchema).optional(),
    header_mapping: z.record(z.string(), z.string()).optional(),
    body_mapping: mappingObjectSchema.optional(),
  }),
  response_mapping: z.object({
    success_condition: z.string().min(1),
    error_mappings: z.array(errorMappingSchema).optional(),
    claims: mappingObjectSchema,
  }),
  encrypted_claims: encryptedClaimsSchema.optional(),
  jwt: sharedJwtSchema,
  log: logConfigSchema,
});

/**
 * Custom login: an operator-supplied JavaScript module decides the outcome.
 *
 * For login flows too specific to express as `direct` credentials or a `delegated` HTTP call -
 * project-specific rules, several upstreams consulted together, bespoke signature schemes. The
 * module returns the claims to mint; this service still signs the token, so `jwt` and
 * `encrypted_claims` behave exactly as for any other strategy.
 *
 * NOTE this is arbitrary code running in-process with the service's privileges. The handler is
 * deployment code, not user input: whoever can set `handler` can already set the signing key.
 */
const customStrategySchema = z.object({
  name: z.string().min(1),
  type: z.literal('custom'),
  inbound_auth: inboundAuthSchema.optional(),
  /** Path to the module. Loaded at STARTUP, so a bad path fails the container, not a login. */
  handler: z.string().min(1),
  /**
   * Named export to call. Defaults to `default`, falling back to `authenticate`, so a module can
   * use either without configuration.
   */
  handler_export: z.string().min(1).optional(),
  /** Budget for the handler. A login path must not hang on someone else's code. */
  timeout_ms: z.number().int().positive().optional().default(5000),
  /** Arbitrary configuration handed to the handler, so a module stays environment-agnostic. */
  options: z.record(z.string(), z.unknown()).optional(),
  /**
   * Optional reshaping of what the handler returned, with its result at `$.handler`. Omit it and
   * the returned object IS the claims.
   */
  claims: mappingObjectSchema.optional(),
  encrypted_claims: encryptedClaimsSchema.optional(),
  jwt: sharedJwtSchema,
});

const strategySchema = z.discriminatedUnion('type', [
  directStrategySchema,
  delegatedStrategySchema,
  jwtStrategySchema,
  customStrategySchema,
]);

export const tokenWeaverConfigSchema = z
  .object({
    strategies: z.array(strategySchema).min(1),
  })
  .superRefine((value, ctx) => {
    const strategyNames = new Set<string>();
    for (const strategy of value.strategies) {
      if (strategyNames.has(strategy.name)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `Strategy names must be unique: ${strategy.name}`,
          path: ['strategies'],
        });
      }
      strategyNames.add(strategy.name);

      if (strategy.type === 'jwt' && strategy.clients) {
        const seen = new Set<string>();
        for (const client of strategy.clients) {
          if (seen.has(client.client_id)) {
            ctx.addIssue({
              code: z.ZodIssueCode.custom,
              message: `Strategy ${strategy.name}: duplicate clients.client_id '${client.client_id}'`,
              path: ['strategies'],
            });
          }
          seen.add(client.client_id);
        }
      }

      // The encrypted blob is written over the mapped public claims, so a name shared with one
      // of them would silently replace a claim the config says to publish.
      const encryptedClaims = strategy.encrypted_claims;
      if (encryptedClaims) {
        const publicClaimNames =
          strategy.type === 'direct'
            ? strategy.credentials.flatMap((credential) => Object.keys(credential.claims))
            : strategy.type === 'custom'
              ? Object.keys(strategy.claims ?? {})
              : strategy.type === 'jwt'
                ? [
                  ...Object.keys(strategy.claims),
                    ...(strategy.clients ?? []).flatMap((client) => Object.keys(client.claims)),
                  ]
                : Object.keys(strategy.response_mapping.claims);

        if (publicClaimNames.includes(encryptedClaims.claim)) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message:
              `Strategy ${strategy.name}: encrypted_claims.claim '${encryptedClaims.claim}' ` +
              'is also a mapped public claim',
            path: ['strategies'],
          });
        }
      }
    }

    const reservedStrategyNames = value.strategies
      .filter((strategy) => strategy.name === 'health' || strategy.name === '.well-known')
      .map((strategy) => strategy.name);

    if (reservedStrategyNames.length > 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `Strategy names are reserved and cannot be used: ${reservedStrategyNames
          .join(', ')}`,
        path: ['strategies'],
      });
    }
  });

export type TokenWeaverConfig = z.infer<typeof tokenWeaverConfigSchema>;
export type StrategyConfig = TokenWeaverConfig['strategies'][number];
export type DirectStrategyConfig = Extract<StrategyConfig, { type: 'direct' }>;
export type DelegatedStrategyConfig = Extract<StrategyConfig, { type: 'delegated' }>;
export type JwtStrategyConfig = Extract<StrategyConfig, { type: 'jwt' }>;
export type CustomStrategyConfig = Extract<StrategyConfig, { type: 'custom' }>;
export type DirectCredential = DirectStrategyConfig['credentials'][number];
export type InboundAuthConfig = NonNullable<StrategyConfig['inbound_auth']>;
export type JwtConfig = StrategyConfig['jwt'];
export type ErrorMappingConfig = z.infer<typeof errorMappingSchema>;
export type EncryptedClaimsConfig = z.infer<typeof encryptedClaimsSchema>;
export type DelegatedLogConfig = z.infer<typeof logConfigSchema>;

function resolveEnvPlaceholders(value: string): string {
  return value.replace(/\$\{([A-Z0-9_]+)\}/gi, (_match, variableName: string) => {
    const resolved = process.env[variableName];
    if (resolved === undefined) {
      throw new HttpError(
        500,
        `Environment variable ${variableName} is required by Token Weaver config`,
      );
    }

    return resolved;
  });
}

function resolveDeep(value: unknown): unknown {
  if (typeof value === 'string') {
    return resolveEnvPlaceholders(value);
  }

  if (Array.isArray(value)) {
    return value.map((item) => resolveDeep(item));
  }

  if (value && typeof value === 'object') {
    const entries = Object.entries(value).map(([key, currentValue]) => [
      key,
      resolveDeep(currentValue),
    ]);
    return Object.fromEntries(entries);
  }

  return value;
}

function parseConfigFile(fileContent: string, configPath: string): unknown {
  const extension = extname(configPath).toLowerCase();

  try {
    if (extension === '.json') {
      return JSON.parse(fileContent) as unknown;
    }

    return YAML.parse(fileContent) as unknown;
  } catch (error) {
    throw new HttpError(
      500,
      `Failed to parse Token Weaver config at ${configPath}: ${
        error instanceof Error ? error.message : 'unknown parse error'
      }`,
    );
  }
}

export function loadTokenWeaverConfig(): TokenWeaverConfig {
  const configPath = env.TOKEN_WEAVER_CONFIG_PATH;
  if (!existsSync(configPath)) {
    throw new HttpError(500, `Token Weaver config file not found at ${configPath}`);
  }

  const fileContent = readFileSync(configPath, 'utf8');
  const parsed = parseConfigFile(fileContent, configPath);
  const resolved = resolveDeep(parsed);

  const result = tokenWeaverConfigSchema.safeParse(resolved);
  if (!result.success) {
    const issues = result.error.issues
      .map((issue) => `  - ${issue.path.join('.') || 'config'}: ${issue.message}`)
      .join('\n');
    throw new HttpError(500, `Token Weaver config validation failed:\n${issues}`);
  }

  return result.data;
}
