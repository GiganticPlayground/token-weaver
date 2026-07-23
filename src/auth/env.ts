import type { RequestHandler } from 'express';

import { createAuthMiddleware } from './auth.middleware';
import type { AuthMiddlewareOptions, AuthPaths, AuthRequirement } from './types';

type EnvReader = (name: string) => string | undefined;

export interface FromEnvOptions {
  /** Env var name prefix. Default `'AUTH_'`. Lets multiple instances coexist. */
  prefix?: string;
  /** Source of env vars. Default `process.env`. */
  env?: NodeJS.ProcessEnv;
  /** Optional post-verification hook — cannot be expressed via env vars. */
  onVerified?: AuthMiddlewareOptions['onVerified'];
}

/** Parse a comma-separated pattern list, trimming blanks. Returns undefined when unset. */
function readPatternList(read: EnvReader, name: string): string[] | undefined {
  const raw = read(name);
  if (raw === undefined) {
    return undefined;
  }
  const patterns = raw
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
  return patterns.length > 0 ? patterns : undefined;
}

function readPaths(read: EnvReader): AuthPaths | undefined {
  const pathPrefix = read('PATH_PREFIX');
  const whitelistClaim = read('WHITELIST_CLAIM');
  const blacklistClaim = read('BLACKLIST_CLAIM');
  // Inline patterns (comma-separated) — usable without JWT claims, e.g. to scope a static token.
  const whitelist = readPatternList(read, 'WHITELIST');
  const blacklist = readPatternList(read, 'BLACKLIST');

  if (
    pathPrefix === undefined &&
    whitelistClaim === undefined &&
    blacklistClaim === undefined &&
    whitelist === undefined &&
    blacklist === undefined
  ) {
    return undefined;
  }

  const paths: AuthPaths = {};
  if (pathPrefix !== undefined) paths.pathPrefix = pathPrefix;
  if (whitelistClaim !== undefined) paths.whitelistClaim = whitelistClaim;
  if (blacklistClaim !== undefined) paths.blacklistClaim = blacklistClaim;
  if (whitelist !== undefined) paths.whitelist = whitelist;
  if (blacklist !== undefined) paths.blacklist = blacklist;
  return paths;
}

function validateRequirement(entry: unknown, ctx: string): AuthRequirement {
  if (typeof entry !== 'object' || entry === null) {
    throw new Error(`createAuthMiddlewareFromEnv: ${ctx} must be an object`);
  }

  const record = entry as Record<string, unknown>;
  const type = record['type'];
  const value = record['value'];

  if (type === 'scope') {
    if (typeof value !== 'string' || value.length === 0) {
      throw new Error(`createAuthMiddlewareFromEnv: ${ctx} 'scope' requires a non-empty 'value'`);
    }
    return { type: 'scope', value };
  }

  if (type === 'claim_includes') {
    const claim = record['claim'];
    if (typeof claim !== 'string' || claim.length === 0) {
      throw new Error(
        `createAuthMiddlewareFromEnv: ${ctx} 'claim_includes' requires a non-empty 'claim'`,
      );
    }
    if (typeof value !== 'string' || value.length === 0) {
      throw new Error(
        `createAuthMiddlewareFromEnv: ${ctx} 'claim_includes' requires a non-empty 'value'`,
      );
    }
    return { type: 'claim_includes', claim, value };
  }

  throw new Error(
    `createAuthMiddlewareFromEnv: ${ctx} has unknown 'type' (expected 'scope' or 'claim_includes')`,
  );
}

function readRequirements(read: EnvReader, prefix: string): AuthRequirement[] {
  const raw = read('REQUIREMENTS');
  if (raw === undefined) {
    return [];
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new Error(`createAuthMiddlewareFromEnv: ${prefix}REQUIREMENTS must be valid JSON`, {
      cause: error,
    });
  }

  if (!Array.isArray(parsed)) {
    throw new Error(`createAuthMiddlewareFromEnv: ${prefix}REQUIREMENTS must be a JSON array`);
  }

  return parsed.map((entry, index) =>
    validateRequirement(entry, `${prefix}REQUIREMENTS[${index}]`),
  );
}

/**
 * Build a {@link createAuthMiddleware} instance from environment variables.
 *
 * Reads (with the configurable `prefix`, default `AUTH_`):
 * `MODE`, `ISSUER`, `AUDIENCE`, `JWKS_URI`, `SECRET`, `STATIC_TOKEN`,
 * `PATH_PREFIX`, `WHITELIST_CLAIM`, `BLACKLIST_CLAIM`, `WHITELIST`/`BLACKLIST`
 * (comma-separated inline path patterns, usable in `static` mode), and
 * `REQUIREMENTS` (a JSON array, e.g. `[{"type":"scope","value":"nexus:read"}]`).
 *
 * Mode-specific required fields are validated by `createAuthMiddleware` (fail fast).
 */
export function createAuthMiddlewareFromEnv(opts: FromEnvOptions = {}): RequestHandler {
  const prefix = opts.prefix ?? 'AUTH_';
  const env = opts.env ?? process.env;

  const read: EnvReader = (name) => {
    const value = env[`${prefix}${name}`];
    return value === undefined || value === '' ? undefined : value;
  };

  const mode = read('MODE');
  if (mode !== 'jwt-jwks' && mode !== 'jwt-hs256' && mode !== 'static') {
    throw new Error(
      `createAuthMiddlewareFromEnv: ${prefix}MODE must be 'jwt-jwks', 'jwt-hs256', or 'static' (got ${
        mode ?? 'undefined'
      })`,
    );
  }

  const options: AuthMiddlewareOptions = { mode };

  const issuer = read('ISSUER');
  if (issuer !== undefined) options.issuer = issuer;
  const audience = read('AUDIENCE');
  if (audience !== undefined) options.audience = audience;
  const jwksUri = read('JWKS_URI');
  if (jwksUri !== undefined) options.jwksUri = jwksUri;
  const secret = read('SECRET');
  if (secret !== undefined) options.secret = secret;
  const staticToken = read('STATIC_TOKEN');
  if (staticToken !== undefined) options.staticToken = staticToken;

  const paths = readPaths(read);
  if (paths !== undefined) options.paths = paths;

  const requirements = readRequirements(read, prefix);
  if (requirements.length > 0) options.requirements = requirements;

  if (opts.onVerified !== undefined) options.onVerified = opts.onVerified;

  return createAuthMiddleware(options);
}
