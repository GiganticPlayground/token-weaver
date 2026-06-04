import type { Request } from 'express';
import type { JWTPayload } from 'jose';

/**
 * Verification mode. Exactly one is active per middleware instance.
 *
 * - `jwt-jwks`  — verify an RS256 JWT against a remote JWKS endpoint.
 * - `jwt-hs256` — verify an HS256 JWT against a shared secret.
 * - `static`    — constant-time compare the bearer value to a fixed token (no JWT).
 */
export type AuthMode = 'jwt-jwks' | 'jwt-hs256' | 'static';

/**
 * Optional authorization requirement checked against the verified JWT payload.
 *
 * - `scope` — the token's `scope` claim (array or space-separated string) must include `value`.
 * - `claim_includes` — the named `claim` (array or space-separated string) must include `value`.
 */
export type AuthRequirement =
  | { type: 'scope'; value: string }
  | { type: 'claim_includes'; claim: string; value: string };

/**
 * Optional path allow/deny configuration. The allow/deny patterns themselves live in the
 * token's claims (named by `whitelistClaim`/`blacklistClaim`) — this only names which claims
 * to read and how to normalize the request path. Glob `*` is supported in patterns.
 */
export interface AuthPaths {
  /** Stripped from the request path before matching (e.g. a mount prefix). */
  pathPrefix?: string;
  /** Claim holding allowed path patterns. If present on the token, at least one must match. */
  whitelistClaim?: string;
  /** Claim holding denied path patterns. A match denies (wins over the whitelist). */
  blacklistClaim?: string;
}

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
  /** Required when `mode === 'jwt-jwks'`. */
  jwksUri?: string;
  /** Required when `mode === 'jwt-hs256'`. */
  secret?: string;
  /** Required when `mode === 'static'`. */
  staticToken?: string;
  /**
   * Optional authorization checks run after a successful verification. Each must pass or the
   * request is rejected with 403. Ignored in `static` mode (no claims to check).
   */
  requirements?: AuthRequirement[];
  /**
   * Optional per-endpoint allow/deny enforced against the token's claims. Ignored in `static`
   * mode. A request that resolves to a denied path is rejected with 403.
   */
  paths?: AuthPaths;
  /**
   * Optional hook invoked after a successful verification and authorization. Lets a consumer
   * map claims onto its own request shape without the library hard-coding them. For `static`
   * mode the payload is an empty object.
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

/**
 * Framework-neutral authorization error. Raised when a token is valid (authenticated) but does
 * not satisfy a configured requirement or path rule. Carries an HTTP `status` of 403.
 */
export class ForbiddenError extends Error {
  readonly status: number;

  constructor(message = 'Forbidden', options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'FORBIDDEN';
    this.status = 403;
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
