/**
 * Public library entry: configurable JWT verification, framework-agnostic core plus an
 * Express middleware wrapper.
 *
 * Imports only `jose` and Express types — it must NOT pull in token-weaver's
 * server or issuing internals. Consume via the `token-weaver/auth` subpath.
 */
export {
  authenticate,
  compileAuth,
  checkPathAccess,
  extractBearerToken,
  type AuthenticateInput,
  type CompiledAuth,
} from './auth.core';
export { createAuthMiddleware } from './auth.middleware';
export { createAuthMiddlewareFromEnv, type FromEnvOptions } from './env';
export { AuthError, ForbiddenError } from './types';
export type {
  AuthMiddlewareOptions,
  AuthMode,
  AuthPaths,
  AuthRequirement,
  AuthStrategyOptions,
  MultiStrategyAuthOptions,
} from './types';
export type { JWTPayload } from 'jose';
