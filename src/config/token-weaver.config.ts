import { existsSync, readFileSync } from 'fs';
import { extname } from 'path';

import YAML from 'yaml';

import { config as env } from './index';
import type {
  DelegatedStrategyConfig,
  InboundAuthConfig,
  MappingObject,
  RouteRule,
  StrategyConfig,
  TokenWeaverConfig,
  UpstreamAuthConfig,
} from '../types/token-weaver';
import { HttpError } from '../utils/http-error';

function coerceString(value: unknown, message: string): string {
  if (typeof value === 'string') {
    return value;
  }

  if (typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }

  throw new HttpError(500, message);
}

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

function ensureRecord(value: unknown, message: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new HttpError(500, message);
  }

  return value as Record<string, unknown>;
}

function parseRouteRule(value: unknown): RouteRule | undefined {
  if (value === undefined) {
    return undefined;
  }

  const route = ensureRecord(value, 'Strategy route must be an object');
  return {
    path: typeof route.path === 'string' ? route.path : undefined,
    headers:
      route.headers && typeof route.headers === 'object'
        ? Object.fromEntries(
            Object.entries(route.headers as Record<string, unknown>).map(([key, currentValue]) => [
              key.toLowerCase(),
              coerceString(
                currentValue,
                `route.headers.${key} must be a string, number, or boolean`,
              ),
            ]),
          )
        : undefined,
    query:
      route.query && typeof route.query === 'object'
        ? Object.fromEntries(
            Object.entries(route.query as Record<string, unknown>).map(([key, currentValue]) => [
              key,
              coerceString(currentValue, `route.query.${key} must be a string, number, or boolean`),
            ]),
          )
        : undefined,
  };
}

function parseInboundAuth(value: unknown): InboundAuthConfig | undefined {
  if (value === undefined) {
    return undefined;
  }

  const inboundAuth = ensureRecord(value, 'inbound_auth must be an object');
  const type = inboundAuth.type;
  if (type !== 'bearer' && type !== 'api_key' && type !== 'none') {
    throw new HttpError(500, 'inbound_auth.type must be bearer, api_key, or none');
  }

  return {
    type,
    header: typeof inboundAuth.header === 'string' ? inboundAuth.header : undefined,
    key: typeof inboundAuth.key === 'string' ? inboundAuth.key : undefined,
    token: typeof inboundAuth.token === 'string' ? inboundAuth.token : undefined,
  };
}

function parseJwt(value: unknown): { issuer: string; ttl: number } {
  const jwt = ensureRecord(value, 'jwt config must be an object');
  if (typeof jwt.issuer !== 'string' || typeof jwt.ttl !== 'number') {
    throw new HttpError(500, 'jwt.issuer must be a string and jwt.ttl must be a number');
  }

  return {
    issuer: jwt.issuer,
    ttl: jwt.ttl,
  };
}

function parseClaims(value: unknown, message: string): MappingObject {
  return ensureRecord(value, message) as MappingObject;
}

function parseUpstreamAuth(value: unknown): UpstreamAuthConfig | undefined {
  if (value === undefined) {
    return undefined;
  }

  const auth = ensureRecord(value, 'upstream.auth must be an object');
  const type = auth.type;
  if (type !== 'bearer' && type !== 'api_key' && type !== 'none') {
    throw new HttpError(500, 'upstream.auth.type must be bearer, api_key, or none');
  }

  return {
    type,
    token: typeof auth.token === 'string' ? auth.token : undefined,
    key: typeof auth.key === 'string' ? auth.key : undefined,
    header: typeof auth.header === 'string' ? auth.header : undefined,
  };
}

function parseDelegatedStrategy(base: Record<string, unknown>): DelegatedStrategyConfig {
  const strategyName = String(base.name);
  const upstream = ensureRecord(base.upstream, 'delegated strategy requires upstream config');
  const responseMapping = ensureRecord(
    base.response_mapping,
    'delegated strategy requires response_mapping config',
  );

  if (typeof upstream.url !== 'string' || typeof upstream.method !== 'string') {
    throw new HttpError(500, 'upstream.url and upstream.method are required');
  }

  if (typeof responseMapping.success_condition !== 'string') {
    throw new HttpError(500, 'response_mapping.success_condition is required');
  }

  return {
    name: strategyName,
    type: 'delegated',
    route: parseRouteRule(base.route),
    inbound_auth: parseInboundAuth(base.inbound_auth),
    upstream: {
      url: upstream.url,
      method: upstream.method.toUpperCase(),
      timeout_ms: typeof upstream.timeout_ms === 'number' ? upstream.timeout_ms : undefined,
      auth: parseUpstreamAuth(upstream.auth),
      headers:
        upstream.headers && typeof upstream.headers === 'object'
          ? Object.fromEntries(
              Object.entries(upstream.headers as Record<string, unknown>).map(
                ([key, currentValue]) => [
                  key,
                  coerceString(
                    currentValue,
                    `upstream.headers.${key} must be a string, number, or boolean`,
                  ),
                ],
              ),
            )
          : undefined,
      header_mapping:
        upstream.header_mapping && typeof upstream.header_mapping === 'object'
          ? Object.fromEntries(
              Object.entries(upstream.header_mapping as Record<string, unknown>).map(
                ([key, currentValue]) => [
                  key,
                  coerceString(
                    currentValue,
                    `upstream.header_mapping.${key} must be a string expression`,
                  ),
                ],
              ),
            )
          : undefined,
      body_mapping: upstream.body_mapping
        ? parseClaims(upstream.body_mapping, 'upstream.body_mapping must be an object')
        : undefined,
    },
    response_mapping: {
      success_condition: responseMapping.success_condition,
      claims: parseClaims(responseMapping.claims, 'response_mapping.claims must be an object'),
    },
    jwt: parseJwt(base.jwt),
  };
}

function parseStrategy(value: unknown): StrategyConfig {
  const base = ensureRecord(value, 'Each strategy must be an object');
  if (typeof base.name !== 'string') {
    throw new HttpError(500, 'Each strategy requires a name');
  }
  const strategyName = base.name;

  if (base.type === 'direct') {
    if (!Array.isArray(base.credentials)) {
      throw new HttpError(500, 'direct strategy requires a credentials array');
    }

    return {
      name: strategyName,
      type: 'direct',
      route: parseRouteRule(base.route),
      inbound_auth: parseInboundAuth(base.inbound_auth),
      credential_path:
        typeof base.credential_path === 'string' ? base.credential_path : '$.request.body.secret',
      credentials: base.credentials.map((credential) => {
        const parsedCredential = ensureRecord(credential, 'Credential entry must be an object');
        if (typeof parsedCredential.secret !== 'string') {
          throw new HttpError(
            500,
            `Credential entry for strategy ${strategyName} must define secret`,
          );
        }

        return {
          secret: parsedCredential.secret,
          claims: parseClaims(
            parsedCredential.claims,
            `Credential claims for strategy ${strategyName} must be an object`,
          ),
        };
      }),
      jwt: parseJwt(base.jwt),
    };
  }

  if (base.type === 'delegated') {
    return parseDelegatedStrategy(base);
  }

  throw new HttpError(500, `Unsupported strategy type for ${String(base.name)}`);
}

function assertUniqueDefaultRoutes(strategies: StrategyConfig[]): void {
  const defaultedStrategies = strategies.filter(
    (strategy) => (strategy.route?.path ?? '/auth') === '/auth',
  );
  const ambiguous = defaultedStrategies.filter(
    (strategy) => !strategy.route?.headers && !strategy.route?.query,
  );

  if (ambiguous.length > 1) {
    throw new HttpError(
      500,
      `Multiple strategies share the default /auth route without discriminators: ${ambiguous
        .map((strategy) => strategy.name)
        .join(', ')}`,
    );
  }
}

export function loadTokenWeaverConfig(): TokenWeaverConfig {
  const configPath = env.TOKEN_WEAVER_CONFIG_PATH;
  if (!existsSync(configPath)) {
    throw new HttpError(500, `Token Weaver config file not found at ${configPath}`);
  }

  const fileContent = readFileSync(configPath, 'utf8');
  const extension = extname(configPath).toLowerCase();
  const parsed: unknown =
    extension === '.json' ? (JSON.parse(fileContent) as unknown) : YAML.parse(fileContent);
  const resolved = resolveDeep(parsed) as TokenWeaverConfig;

  if (!resolved || !Array.isArray(resolved.strategies) || resolved.strategies.length === 0) {
    throw new HttpError(500, 'Token Weaver config must define at least one strategy');
  }

  const strategies = resolved.strategies.map((strategy) => parseStrategy(strategy));
  assertUniqueDefaultRoutes(strategies);

  return { strategies };
}
