/**
 * Public library entry: a configurable JWT-verification Express middleware.
 *
 * Imports only `jose` and Express types — it must NOT pull in token-weaver's
 * server or issuing internals. Consume via the `token-weaver/auth` subpath.
 */
export { createAuthMiddleware } from './auth.middleware';
export { AuthError } from './types';
export type { AuthMiddlewareOptions, AuthMode } from './types';
export type { JWTPayload } from 'jose';
