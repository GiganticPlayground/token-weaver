import { timingSafeEqual } from 'crypto';
import { URL } from 'url';
import { TextEncoder } from 'util';

import { createRemoteJWKSet, jwtVerify, type JWTPayload, type JWTVerifyOptions } from 'jose';

import {
  AuthError,
  ForbiddenError,
  type AuthMiddlewareOptions,
  type AuthPaths,
  type AuthRequirement,
  type AuthStrategyOptions,
  type MultiStrategyAuthOptions,
} from './types';

/**
 * Framework-agnostic authentication core.
 *
 * Everything in this module operates on plain values (an Authorization header string and an
 * optional path/operation identifier) so it can be consumed outside Express — from any HTTP
 * framework, a message pipeline, or a rules engine. The Express middleware in
 * `auth.middleware.ts` is a thin wrapper over this module.
 */

/** Input to a compiled authenticator: plain values extracted from whatever carried the request. */
export interface AuthenticateInput {
  /** Raw Authorization header value (e.g. `"Bearer eyJ..."`). */
  authorizationHeader?: string | undefined;
  /**
   * Identifier matched against `paths` whitelist/blacklist rules. Any opaque string works — a
   * URL path or a canonical operation/route name. Required when a strategy configures `paths`;
   * omitting it while `paths` is configured fails closed (403).
   */
  path?: string | undefined;
}

/** A compiled verify+authorize pipeline: returns the payload or throws AuthError/ForbiddenError. */
export type CompiledAuth = (input: AuthenticateInput) => Promise<JWTPayload>;

/** A resolved per-request verifier: returns the decoded payload or throws AuthError. */
type InputVerifier = (input: AuthenticateInput) => Promise<JWTPayload>;

/** A resolved authorizer: throws ForbiddenError if the payload/input is not permitted. */
type Authorizer = (payload: JWTPayload, input: AuthenticateInput) => void;

function configError(field: string, mode: AuthMiddlewareOptions['mode']): Error {
  return new Error(`compileAuth: '${field}' is required when mode is '${mode}'`);
}

export function extractBearerToken(authorizationHeader: string | undefined): string {
  if (typeof authorizationHeader !== 'string') {
    throw new AuthError('Missing Authorization header');
  }

  const [scheme, token] = authorizationHeader.split(/\s+/, 2);
  if (scheme?.toLowerCase() !== 'bearer' || !token) {
    throw new AuthError('Malformed Authorization header');
  }

  return token;
}

function constantTimeEquals(actual: string, expected: string): boolean {
  const actualBytes = Buffer.from(actual);
  const expectedBytes = Buffer.from(expected);
  // Length comparison short-circuits; timingSafeEqual requires equal-length buffers.
  if (actualBytes.length !== expectedBytes.length) {
    return false;
  }

  return timingSafeEqual(actualBytes, expectedBytes);
}

function buildVerifyOptions(
  issuer: string,
  audience: string | undefined,
  algorithm: 'RS256' | 'HS256',
): JWTVerifyOptions {
  const verifyOptions: JWTVerifyOptions = { algorithms: [algorithm], issuer };
  if (audience !== undefined) {
    verifyOptions.audience = audience;
  }

  return verifyOptions;
}

// --- Optional authorization layer (claims-driven) --------------------------------

/** Coerce a claim into a string list — accepts an array or a space-separated string. */
function toStringArray(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.filter((entry): entry is string => typeof entry === 'string');
  }
  if (typeof value === 'string') {
    return value.split(' ').filter(Boolean);
  }
  return [];
}

function checkRequirement(payload: JWTPayload, requirement: AuthRequirement): boolean {
  switch (requirement.type) {
    case 'scope':
      return toStringArray(payload['scope']).includes(requirement.value);
    case 'claim_includes':
      return toStringArray(payload[requirement.claim]).includes(requirement.value);
  }
}

function normalizePath(path: string): string {
  return path.replace(/^\//, '');
}

/** Compile glob-ish path patterns (`*` → `.*`) into a single anchored, case-insensitive regex. */
function buildPathRegex(patterns: string[]): RegExp {
  const alternation = patterns
    .map((pattern) => {
      const escaped = normalizePath(pattern).replace(/[.+^${}()|[\]\\]/g, '\\$&');
      return `^${escaped.replace(/\*/g, '.*')}$`;
    })
    .join('|');
  return new RegExp(alternation, 'i');
}

/**
 * Resolve an effective pattern list from an inline list and/or a claim name. Inline patterns
 * take precedence; otherwise the named claim is read from the payload. Returns `null` when
 * neither source is active (meaning "no list configured" — unrestricted for that side).
 */
function resolvePatternList(
  inline: string[] | undefined,
  claimName: string | undefined,
  payload: JWTPayload,
): string[] | null {
  if (inline !== undefined) {
    return inline;
  }
  if (claimName !== undefined && payload[claimName] !== undefined) {
    return toStringArray(payload[claimName]);
  }
  return null;
}

/**
 * Whether `path` is permitted by the resolved whitelist/blacklist rules. Patterns are anchored
 * globs (`*` → `.*`, case-insensitive); a whitelist, when present, must match (an empty
 * whitelist denies all); a blacklist match always denies. Exported for consumers that manage
 * their own authorization flow but want identical matching semantics.
 */
export function checkPathAccess(path: string, paths: AuthPaths, payload: JWTPayload = {}): boolean {
  let testPath = path;
  if (paths.pathPrefix && testPath.startsWith(paths.pathPrefix)) {
    testPath = testPath.slice(paths.pathPrefix.length);
  }
  testPath = normalizePath(testPath);

  const whitelist = resolvePatternList(paths.whitelist, paths.whitelistClaim, payload);
  const blacklist = resolvePatternList(paths.blacklist, paths.blacklistClaim, payload);

  // Whitelist: if present, at least one pattern must match (an empty whitelist denies all).
  if (whitelist !== null && (whitelist.length === 0 || !buildPathRegex(whitelist).test(testPath))) {
    return false;
  }

  // Blacklist wins: any match denies.
  if (blacklist !== null && blacklist.length > 0 && buildPathRegex(blacklist).test(testPath)) {
    return false;
  }

  return true;
}

/**
 * Build the optional authorizer from `requirements`/`paths`. Returns `undefined` when no
 * authorization is configured (pure authentication).
 *
 * `requirements` are claim-based, so they are skipped in `static` mode (no claims). `paths`
 * still applies in `static` mode via its inline `whitelist`/`blacklist` (claim-based path
 * lists resolve to nothing without a token, i.e. unrestricted).
 */
function buildAuthorizer(options: AuthStrategyOptions): Authorizer | undefined {
  const requirements = options.mode === 'static' ? [] : (options.requirements ?? []);
  const { paths } = options;
  if (requirements.length === 0 && !paths) {
    return undefined;
  }

  return (payload, input) => {
    for (const requirement of requirements) {
      if (!checkRequirement(payload, requirement)) {
        throw new ForbiddenError(`Token does not satisfy requirement: ${requirement.type}`);
      }
    }

    if (paths) {
      // Paths are configured, so authorization needs a path to test. No path fails closed —
      // silently skipping the check would grant access the configuration says to gate.
      if (input.path === undefined) {
        throw new ForbiddenError('No request path available for path authorization');
      }
      if (!checkPathAccess(input.path, paths, payload)) {
        throw new ForbiddenError(`Token does not permit access to path: ${input.path}`);
      }
    }
  };
}

/**
 * Validate options and build the verifier once. Throws a plain Error on an inconsistent
 * option combination (programmer error, fail fast).
 */
function resolveVerifier(options: AuthStrategyOptions): InputVerifier {
  switch (options.mode) {
    case 'jwt-jwks': {
      const { jwksUri, issuer, audience } = options;
      if (!jwksUri) throw configError('jwksUri', 'jwt-jwks');
      if (!issuer) throw configError('issuer', 'jwt-jwks');

      const jwks = createRemoteJWKSet(new URL(jwksUri));
      const verifyOptions = buildVerifyOptions(issuer, audience, 'RS256');

      return async (input) => {
        const token = extractBearerToken(input.authorizationHeader);
        try {
          const { payload } = await jwtVerify(token, jwks, verifyOptions);
          return payload;
        } catch (error) {
          throw new AuthError('Invalid or expired token', { cause: error });
        }
      };
    }

    case 'jwt-hs256': {
      const { secret, issuer, audience } = options;
      if (!secret) throw configError('secret', 'jwt-hs256');
      if (!issuer) throw configError('issuer', 'jwt-hs256');

      const key = new TextEncoder().encode(secret);
      const verifyOptions = buildVerifyOptions(issuer, audience, 'HS256');

      return async (input) => {
        const token = extractBearerToken(input.authorizationHeader);
        try {
          const { payload } = await jwtVerify(token, key, verifyOptions);
          return payload;
        } catch (error) {
          throw new AuthError('Invalid or expired token', { cause: error });
        }
      };
    }

    case 'static': {
      const { staticToken } = options;
      if (!staticToken) throw configError('staticToken', 'static');

      return async (input) => {
        const token = extractBearerToken(input.authorizationHeader);
        if (!constantTimeEquals(token, staticToken)) {
          throw new AuthError('Invalid token');
        }
        return {};
      };
    }

    default: {
      // Exhaustiveness guard for an out-of-contract mode value.
      const unknownMode: string = options.mode;
      throw new Error(`compileAuth: unknown mode '${unknownMode}'`);
    }
  }
}

/** A verify + optional authorize pair compiled once from a single strategy. */
interface CompiledStrategy {
  verify: InputVerifier;
  authorize: Authorizer | undefined;
}

function compileStrategy(options: AuthStrategyOptions): CompiledStrategy {
  return { verify: resolveVerifier(options), authorize: buildAuthorizer(options) };
}

/** HTTP status carried by AuthError/ForbiddenError; defaults to 401 for anything unexpected. */
function statusOf(error: unknown): number {
  return typeof (error as { status?: unknown }).status === 'number'
    ? (error as { status: number }).status
    : 401;
}

/**
 * Try each strategy in order. The first whose verification AND authorization both pass wins
 * and its payload is returned. If none pass, the most informative failure is thrown — a 403
 * (authenticated but not authorized) is preferred over a 401.
 */
async function authenticateAny(
  strategies: CompiledStrategy[],
  input: AuthenticateInput,
): Promise<JWTPayload> {
  let bestFailure: { status: number; error: Error } | null = null;

  for (const { verify, authorize } of strategies) {
    let payload: JWTPayload;
    try {
      payload = await verify(input);
      if (authorize) {
        authorize(payload, input);
      }
    } catch (caught) {
      // verify/authorize only throw AuthError/ForbiddenError; coerce defensively so we always
      // re-throw a real Error (and satisfy no-throw-literal).
      const error = caught instanceof Error ? caught : new AuthError(String(caught));
      const status = statusOf(error);
      if (bestFailure === null || (bestFailure.status !== 403 && status === 403)) {
        bestFailure = { status, error };
      }
      continue;
    }

    return payload;
  }

  throw bestFailure?.error ?? new AuthError('Authentication failed');
}

/**
 * Compile authentication options into a reusable authenticator. Compile ONCE and reuse per
 * request — `jwt-jwks` strategies hold a remote JWKS key cache inside the compiled instance,
 * so recompiling per request refetches keys.
 *
 * Accepts a **single** strategy ({@link AuthMiddlewareOptions}) or **multiple** strategies
 * ({@link MultiStrategyAuthOptions}) tried in order until one accepts. Failures throw
 * framework-neutral errors: a 401 {@link AuthError} for authentication (missing/invalid
 * token), or a 403 {@link ForbiddenError} for authorization (`requirements`/`paths` not met).
 * With multiple strategies, the surfaced failure prefers a 403 over a 401.
 *
 * NOTE: the `onVerified` hook is an Express-middleware affordance and is NOT invoked here —
 * callers of the core API act on the returned payload directly.
 */
export function compileAuth(options: AuthMiddlewareOptions | MultiStrategyAuthOptions): CompiledAuth {
  const strategies: CompiledStrategy[] = [];
  if ('strategies' in options) {
    if (options.strategies.length === 0) {
      throw new Error('compileAuth: strategies must be a non-empty array');
    }
    for (const strategy of options.strategies) {
      strategies.push(compileStrategy(strategy));
    }
  } else {
    strategies.push(compileStrategy(options));
  }

  return (input) => authenticateAny(strategies, input);
}

/**
 * One-shot convenience over {@link compileAuth}. Prefer `compileAuth` when authenticating
 * repeatedly with the same options (JWKS key caching lives in the compiled instance).
 */
export async function authenticate(
  input: AuthenticateInput,
  options: AuthMiddlewareOptions | MultiStrategyAuthOptions,
): Promise<JWTPayload> {
  return compileAuth(options)(input);
}
