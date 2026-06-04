import type { Request } from 'express';
import type { JWTPayload } from 'jose';

/**
 * Verification mode. Exactly one is active per middleware instance.
 *
 * - `jwks`   — verify an RS256 JWT against a remote JWKS endpoint.
 * - `secret` — verify an HS256 JWT against a shared secret.
 * - `static` — constant-time compare the bearer value to a fixed token (no JWT).
 */
export type AuthMode = 'jwks' | 'secret' | 'static';

/**
 * Options for {@link createAuthMiddleware}. Validated at construction time;
 * an inconsistent combination throws synchronously (fail fast).
 */
export interface AuthMiddlewareOptions {
  mode: AuthMode;
  /** Required for `jwks` and `secret`. Enforced during verification. */
  issuer?: string;
  /** Optional audience check, applied to `jwks` and `secret`. */
  audience?: string;
  /** Required when `mode === 'jwks'`. */
  jwksUri?: string;
  /** Required when `mode === 'secret'`. */
  secret?: string;
  /** Required when `mode === 'static'`. */
  staticToken?: string;
  /**
   * Optional hook invoked after a successful verification. Lets a consumer map
   * claims onto its own request shape without the library hard-coding them.
   * For `static` mode the payload is an empty object.
   */
  onVerified?: (payload: JWTPayload, req: Request) => void | Promise<void>;
}

/**
 * Framework-neutral authentication error. Carries an HTTP `status` of 401 so a
 * consumer's error middleware can render it, without coupling to this repo's
 * server-side error types.
 */
export class AuthError extends Error {
  readonly status: number;

  constructor(message = 'Unauthorized', options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'UNAUTHORIZED';
    this.status = 401;
  }
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      /** Decoded JWT payload attached on successful verification. */
      jwtPayload?: JWTPayload;
    }
  }
}
