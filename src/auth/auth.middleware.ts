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

function checkPaths(reqPath: string, payload: JWTPayload, paths: AuthPaths): boolean {
  let testPath = reqPath;
  if (paths.pathPrefix && testPath.startsWith(paths.pathPrefix)) {
    testPath = testPath.slice(paths.pathPrefix.length);
  }
  testPath = normalizePath(testPath);

  const whitelist =
    paths.whitelistClaim !== undefined && payload[paths.whitelistClaim] !== undefined
      ? toStringArray(payload[paths.whitelistClaim])
      : null;
  const blacklist =
    paths.blacklistClaim !== undefined && payload[paths.blacklistClaim] !== undefined
      ? toStringArray(payload[paths.blacklistClaim])
      : null;

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
 * authorization is configured (pure authentication). Not used in `static` mode.
 */
function buildAuthorizer(options: AuthMiddlewareOptions): Authorizer | undefined {
  const requirements = options.requirements ?? [];
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
function resolveVerifier(options: AuthMiddlewareOptions): RequestVerifier {
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

async function authenticate(
  verify: RequestVerifier,
  authorize: Authorizer | undefined,
  onVerified: AuthMiddlewareOptions['onVerified'],
  req: Request,
): Promise<void> {
  const payload = await verify(req);
  if (authorize) {
    authorize(payload, req);
  }
  req.jwtPayload = payload;
  if (onVerified) {
    await onVerified(payload, req);
  }
}

/**
 * Create a configurable JWT-verification Express middleware. Exactly one mode
 * is active per instance. On success the decoded payload is attached to
 * `req.jwtPayload` and `onVerified` (if provided) is awaited.
 *
 * Failures are passed to `next()` as framework-neutral errors: a 401
 * {@link AuthError} for authentication (missing/invalid token), or a 403
 * {@link ForbiddenError} for authorization (`requirements`/`paths` not met).
 * Authorization is skipped in `static` mode (no claims to check).
 */
export function createAuthMiddleware(options: AuthMiddlewareOptions): RequestHandler {
  const verify = resolveVerifier(options);
  const authorize = options.mode === 'static' ? undefined : buildAuthorizer(options);
  const { onVerified } = options;

  return (req: Request, _res: Response, next: NextFunction): void => {
    void authenticate(verify, authorize, onVerified, req).then(
      () => next(),
      (error: unknown) => next(error),
    );
  };
}
