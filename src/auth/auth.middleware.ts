import { timingSafeEqual } from 'crypto';
import { URL } from 'url';
import { TextEncoder } from 'util';

import type { NextFunction, Request, RequestHandler, Response } from 'express';
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

/** A resolved per-request verifier: returns the decoded payload or throws AuthError. */
type RequestVerifier = (req: Request) => Promise<JWTPayload>;

/** A resolved authorizer: throws ForbiddenError if the payload/request is not permitted. */
type Authorizer = (payload: JWTPayload, req: Request) => void;

function configError(field: string, mode: AuthMiddlewareOptions['mode']): Error {
  return new Error(`createAuthMiddleware: '${field}' is required when mode is '${mode}'`);
}

function extractBearer(req: Request): string {
  const header = req.headers.authorization;
  if (typeof header !== 'string') {
    throw new AuthError('Missing Authorization header');
  }

  const [scheme, token] = header.split(/\s+/, 2);
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

// --- Optional authorization layer (claims-driven; ported from ipb-nexus) --------

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

function checkPaths(reqPath: string, payload: JWTPayload, paths: AuthPaths): boolean {
  let testPath = reqPath;
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

  return (payload, req) => {
    for (const requirement of requirements) {
      if (!checkRequirement(payload, requirement)) {
        throw new ForbiddenError(`Token does not satisfy requirement: ${requirement.type}`);
      }
    }

    if (paths) {
      const fullPath = `${req.baseUrl}${req.path}`;
      if (!checkPaths(fullPath, payload, paths)) {
        throw new ForbiddenError(`Token does not permit access to path: ${fullPath}`);
      }
    }
  };
}

/**
 * Validate options and build the per-request verifier once. Throws a plain
 * Error on an inconsistent option combination (programmer error, fail fast).
 */
function resolveVerifier(options: AuthStrategyOptions): RequestVerifier {
  switch (options.mode) {
    case 'jwt-jwks': {
      const { jwksUri, issuer, audience } = options;
      if (!jwksUri) throw configError('jwksUri', 'jwt-jwks');
      if (!issuer) throw configError('issuer', 'jwt-jwks');

      const jwks = createRemoteJWKSet(new URL(jwksUri));
      const verifyOptions = buildVerifyOptions(issuer, audience, 'RS256');

      return async (req) => {
        const token = extractBearer(req);
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

      return async (req) => {
        const token = extractBearer(req);
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

      return async (req) => {
        const token = extractBearer(req);
        if (!constantTimeEquals(token, staticToken)) {
          throw new AuthError('Invalid token');
        }
        return {};
      };
    }

    default: {
      // Exhaustiveness guard for an out-of-contract mode value.
      const unknownMode: string = options.mode;
      throw new Error(`createAuthMiddleware: unknown mode '${unknownMode}'`);
    }
  }
}

/** A verify + optional authorize pair compiled once from a single strategy. */
interface CompiledStrategy {
  verify: RequestVerifier;
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
 * Try each strategy in order. The first whose verification AND authorization both pass wins:
 * its payload is attached and the shared `onVerified` runs. If none pass, the most informative
 * failure is thrown — a 403 (authenticated but not authorized) is preferred over a 401.
 *
 * `onVerified` runs only for the winning strategy and its errors propagate directly (a consumer
 * rejection is final — we do not fall through to another strategy).
 */
async function authenticateAny(
  strategies: CompiledStrategy[],
  onVerified: MultiStrategyAuthOptions['onVerified'],
  req: Request,
): Promise<void> {
  let bestFailure: { status: number; error: Error } | null = null;

  for (const { verify, authorize } of strategies) {
    let payload: JWTPayload;
    try {
      payload = await verify(req);
      if (authorize) {
        authorize(payload, req);
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

    // Committed to this strategy — verification + authorization passed.
    req.jwtPayload = payload;
    if (onVerified) {
      await onVerified(payload, req);
    }
    return;
  }

  throw bestFailure?.error ?? new AuthError('Authentication failed');
}

/**
 * Create a configurable JWT-verification Express middleware.
 *
 * Accepts either a **single** strategy ({@link AuthMiddlewareOptions}) or **multiple**
 * strategies ({@link MultiStrategyAuthOptions}) tried in order until one accepts the request.
 * On success the decoded payload is attached to `req.jwtPayload` and `onVerified` (if provided)
 * is awaited once for the winning strategy.
 *
 * Failures are passed to `next()` as framework-neutral errors: a 401 {@link AuthError} for
 * authentication (missing/invalid token), or a 403 {@link ForbiddenError} for authorization
 * (`requirements`/`paths` not met). With multiple strategies, the surfaced failure prefers a
 * 403 over a 401. Claim-based `requirements` are skipped in `static` mode; inline `paths`
 * (`whitelist`/`blacklist`) still apply.
 */
export function createAuthMiddleware(
  options: AuthMiddlewareOptions | MultiStrategyAuthOptions,
): RequestHandler {
  const strategies: CompiledStrategy[] = [];
  if ('strategies' in options) {
    if (options.strategies.length === 0) {
      throw new Error('createAuthMiddleware: strategies must be a non-empty array');
    }
    for (const strategy of options.strategies) {
      strategies.push(compileStrategy(strategy));
    }
  } else {
    strategies.push(compileStrategy(options));
  }
  const { onVerified } = options;

  return (req: Request, _res: Response, next: NextFunction): void => {
    void authenticateAny(strategies, onVerified, req).then(
      () => next(),
      (error: unknown) => next(error),
    );
  };
}
