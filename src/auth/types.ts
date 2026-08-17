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
 * Optional path allow/deny configuration. Glob `*` is supported in patterns.
 *
 * Patterns can come from two sources:
 * - **Inline** (`whitelist`/`blacklist`) — fixed patterns declared in config. These need no
 *   JWT claims, so they are the way to scope a `static` token to specific paths.
 * - **Claim-based** (`whitelistClaim`/`blacklistClaim`) — names of JWT claims that carry the
 *   patterns; only meaningful for the JWT modes (a `static` token has no claims).
 *
 * When both an inline list and a claim are given for the same side, the inline list takes
 * precedence. A blacklist match always wins over the whitelist.
 */
export interface AuthPaths {
  /** Stripped from the request path before matching (e.g. a mount prefix). */
  pathPrefix?: string;
  /** Inline allowed path patterns. If present, at least one must match. */
  whitelist?: string[];
  /** Inline denied path patterns. A match denies (wins over the whitelist). */
  blacklist?: string[];
  /** Claim holding allowed path patterns. If present on the token, at least one must match. */
  whitelistClaim?: string;
  /** Claim holding denied path patterns. A match denies (wins over the whitelist). */
  blacklistClaim?: string;
}

/**
 * Optional decryption of an encrypted claim blob carried inside the verified JWT.
 *
 * Token Weaver can encrypt a group of claims into a single opaque claim (a compact JWE) so a
 * frontend holding the token cannot read them. Configure this with the matching shared secret
 * and, after verification, that claim holds the decrypted object instead of the ciphertext
 * string — read it from `req.jwtPayload[claim]` (or via `readEncryptedClaims`).
 *
 * Ignored in `static` mode, which has no claims.
 */
export interface AuthEncryptedClaims {
  /**
   * Shared secret: a 32-byte key as base64 or hex. Pass several to accept more than one during
   * a rotation — they are tried in order.
   */
  secret: string | string[];
  /** Claim carrying the blob. Default `enc`. */
  claim?: string;
  /**
   * Whether the blob must be present. Default `true`: a token without it is rejected with 401.
   * Set `false` when only some tokens for this issuer carry encrypted claims. A blob that IS
   * present but fails to decrypt is always a 401, regardless of this setting.
   */
  required?: boolean;
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
   * Optional per-endpoint allow/deny. For JWT modes the patterns come from the token's claims
   * (`whitelistClaim`/`blacklistClaim`) and/or inline lists; for `static` mode only the inline
   * `whitelist`/`blacklist` apply (no claims). A request that resolves to a denied path is
   * rejected with 403.
   */
  paths?: AuthPaths;
  /**
   * Optional decryption of an encrypted claim blob. When set, the configured claim is decrypted
   * after verification and before authorization, replacing the ciphertext string in the payload
   * with the decrypted object. Ignored in `static` mode.
   */
  encryptedClaims?: AuthEncryptedClaims;
  /**
   * Optional hook invoked after a successful verification and authorization. Lets a consumer
   * map claims onto its own request shape without the library hard-coding them. For `static`
   * mode the payload is an empty object.
   */
  onVerified?: (payload: JWTPayload, req: Request) => void | Promise<void>;
}

/**
 * A single verification strategy — the same shape as {@link AuthMiddlewareOptions} minus the
 * shared `onVerified` hook (which lives on {@link MultiStrategyAuthOptions} so it runs once for
 * whichever strategy wins).
 */
export type AuthStrategyOptions = Omit<AuthMiddlewareOptions, 'onVerified'>;

/**
 * Options for a multi-strategy middleware: several verification strategies tried in order until
 * one accepts the request (the first success wins). Lets a single deployment accept, say, an
 * internal static token AND client JWTs at once. If every strategy rejects, the most informative
 * failure is surfaced — a 403 (authenticated but not authorized) preferred over a 401.
 */
export interface MultiStrategyAuthOptions {
  strategies: AuthStrategyOptions[];
  /** Runs once, after whichever strategy accepts the request. */
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
