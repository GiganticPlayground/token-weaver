import { timingSafeEqual } from 'crypto';
import { URL } from 'url';
import { TextEncoder } from 'util';

import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { createRemoteJWKSet, jwtVerify, type JWTPayload, type JWTVerifyOptions } from 'jose';

import { AuthError, type AuthMiddlewareOptions } from './types';

/** A resolved per-request verifier: returns the decoded payload or throws AuthError. */
type RequestVerifier = (req: Request) => Promise<JWTPayload>;

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

/**
 * Validate options and build the per-request verifier once. Throws a plain
 * Error on an inconsistent option combination (programmer error, fail fast).
 */
function resolveVerifier(options: AuthMiddlewareOptions): RequestVerifier {
  switch (options.mode) {
    case 'jwks': {
      const { jwksUri, issuer, audience } = options;
      if (!jwksUri) throw configError('jwksUri', 'jwks');
      if (!issuer) throw configError('issuer', 'jwks');

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

    case 'secret': {
      const { secret, issuer, audience } = options;
      if (!secret) throw configError('secret', 'secret');
      if (!issuer) throw configError('issuer', 'secret');

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
  onVerified: AuthMiddlewareOptions['onVerified'],
  req: Request,
): Promise<void> {
  const payload = await verify(req);
  req.jwtPayload = payload;
  if (onVerified) {
    await onVerified(payload, req);
  }
}

/**
 * Create a configurable JWT-verification Express middleware. Exactly one mode
 * is active per instance. On success the decoded payload is attached to
 * `req.jwtPayload` and `onVerified` (if provided) is awaited; on any failure a
 * 401 {@link AuthError} is passed to `next()`.
 */
export function createAuthMiddleware(options: AuthMiddlewareOptions): RequestHandler {
  const verify = resolveVerifier(options);
  const { onVerified } = options;

  return (req: Request, _res: Response, next: NextFunction): void => {
    void authenticate(verify, onVerified, req).then(
      () => next(),
      (error: unknown) => next(error),
    );
  };
}
