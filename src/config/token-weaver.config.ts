import { existsSync, readFileSync } from 'fs';
import { extname } from 'path';

import YAML from 'yaml';
import { z } from 'zod';

import { config as env } from './index';
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
  upstream_body_error: z.boolean().optional().default(true),
  upstream_body_success: z.boolean().optional().default(false),
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
  jwt: sharedJwtSchema,
  log: logConfigSchema,
});

const strategySchema = z.discriminatedUnion('type', [
  directStrategySchema,
  delegatedStrategySchema,
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
export type DirectCredential = DirectStrategyConfig['credentials'][number];
export type InboundAuthConfig = NonNullable<StrategyConfig['inbound_auth']>;
export type JwtConfig = StrategyConfig['jwt'];
export type ErrorMappingConfig = z.infer<typeof errorMappingSchema>;
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
