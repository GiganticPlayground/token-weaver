import type { NextFunction, Request, RequestHandler, Response } from 'express';
import type { JWTPayload } from 'jose';

import { compileAuth } from './auth.core';
import type { AuthMiddlewareOptions, MultiStrategyAuthOptions } from './types';

/**
 * Create a configurable JWT-verification Express middleware.
 *
 * A thin wrapper over the framework-agnostic core (`auth.core.ts`): it extracts the
 * Authorization header and request path from the Express request, delegates to the compiled
 * authenticator, attaches the decoded payload to `req.jwtPayload`, and awaits `onVerified`
 * (if provided) once for the winning strategy.
 *
 * Accepts either a **single** strategy ({@link AuthMiddlewareOptions}) or **multiple**
 * strategies ({@link MultiStrategyAuthOptions}) tried in order until one accepts the request.
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
  const authenticate = compileAuth(options);
  const { onVerified } = options;

  const handle = async (req: Request): Promise<void> => {
    const payload: JWTPayload = await authenticate({
      authorizationHeader: req.headers.authorization,
      path: `${req.baseUrl}${req.path}`,
    });

    // Committed to the winning strategy — verification + authorization passed.
    req.jwtPayload = payload;
    if (onVerified) {
      // A consumer rejection is final — errors propagate to next() directly.
      await onVerified(payload, req);
    }
  };

  return (req: Request, _res: Response, next: NextFunction): void => {
    void handle(req).then(
      () => next(),
      (error: unknown) => next(error),
    );
  };
}
