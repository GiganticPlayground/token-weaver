# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Token Weaver is a configurable authentication gateway: it accepts inbound credentials, applies a configured **strategy**, and returns a signed JWT on success. It issues tokens but does not store users — downstream services validate the JWTs via the published JWKS. See `README.md` for the full configuration reference (strategy fields, mapping examples, env var table).

## Commands

```bash
npm run dev          # nodemon + tsx, hot reload from src/index.ts
npm start            # run once via node --import=tsx
npm run gen:keys     # generate a local RSA keypair for RS256 signing
npm run build        # tsc to dist/ then fix ESM imports (see ESM note below)
npm test             # node --test runner over tests/**/*.test.ts
npm run validate     # type-check + lint + format:check (run before committing)
npm run type-check   # tsc --noEmit
npm run lint         # eslint src tests
npm run generate     # regenerate src/types/schema.d.ts AND stub controllers from openapi.yaml
```

Run a single test by name: `node --import=tsx --test --test-name-pattern "<pattern>" tests/e2e/auth.e2e.test.ts`

`tests/e2e/auth.e2e.test.ts` covers the service itself: it spawns it as a child process, stands up a fake upstream HTTP server, generates ephemeral keys, and asserts on issued JWTs. Server behavior is verified only this way — there are no unit tests for the server. The published `src/auth/` library, being server-independent, is tested in-process under `tests/auth/`.

## Required setup before the service runs

The service **fails fast at import time** if either of these is missing:
- A strategy config file (default `config/token-weaver.yaml`; copy from the `.example`). Validated by Zod in `src/config/token-weaver.config.ts`.
- Signing key material *if any strategy uses RS256*: set `TOKEN_WEAVER_PRIVATE_KEY` or `TOKEN_WEAVER_PRIVATE_KEY_PATH`. HS256 strategies need only a `secret` in their config and no RSA key.

Env vars are validated by Zod in `src/config/env.validation.ts` and loaded eagerly via `src/config/index.ts` — invalid env crashes on startup, not on first request.

## Architecture

Two configuration surfaces drive almost all behavior; understand both before changing endpoints or auth logic.

### 1. OpenAPI spec drives routing (not code)

Routes are **not** registered with `app.get/post` in source. `api/openapi.yaml` is the source of truth: `express-openapi-validator` (wired in `src/middlewares/openapi.middleware.ts`, mounted in `src/index.ts`) reads the spec, validates each request, then dispatches to a controller export. The binding is the per-operation `x-eov-operation-handler` (file name in `src/controllers/`) + `x-eov-operation-id` (exported function name).

To add or change an endpoint: edit `api/openapi.yaml`, run `npm run generate` (regenerates `src/types/schema.d.ts` and stubs any new controller file — it skips files that already exist), then implement the controller export. Request validation, body parsing, and the `/auth/{name}` path param all come from the spec.

The three endpoints today: `postAuth` (`POST /auth/{name}`) and `getJwks` (`GET /.well-known/jwks.json`) in `authController.ts`; `getHealth` in `healthController.ts`.

### 2. Strategy config drives auth behavior

`src/services/index.ts` constructs a single `TokenWeaverService` at import, loading and validating the strategy config. The service builds a `Map<strategyName, StrategyConfig>`; `POST /auth/{name}` looks up the strategy by the `{name}` path segment.

Strategy execution lives entirely in `src/services/token-weaver.service.ts`:
- **direct** — read a credential from the request via a `$` path, match it against the configured `credentials` list, map that credential's `claims` into the JWT. No network call.
- **delegated** — build an upstream request (`header_mapping`/`body_mapping`), call it via `src/utils/http-fetch.ts`, evaluate `response_mapping.success_condition`; on success map `claims`, on failure walk `error_mappings` in order (first match, condition-less entry is catch-all) to pick the returned status/message.

Both strategies optionally enforce `inbound_auth` (`api_key`/`bearer`/`none`) before running.

Either strategy may also declare `encrypted_claims`: a second claims block mapped the same way but
encrypted into one opaque claim (default `enc`) instead of published in cleartext — for values a
frontend holding the token must not read. See "Encrypted claims" below.

### Mapping expressions

`src/utils/path-expression.ts` implements the `$.request.body.x` / `$.response.body.y` path resolver and the simple `==` condition evaluator used by `success_condition` and `error_mappings`. The `mapValue` helper in the service recursively resolves any string starting with `$` inside `claims`/`body_mapping` objects against the request (and, for delegated, upstream-response) context. This is the mechanism that turns request/response fields into JWT claims — changes here affect every strategy.

### JWT signing

`src/services/jwt.service.ts` signs payloads with either RS256 (RSA key, public half published at `/.well-known/jwks.json`) or HS256 (shared secret, **not** in JWKS — `getJwks` returns empty keys when no RSA key is loaded). The RSA key is loaded lazily only when at least one strategy declares `algorithm: RS256`. Every issued token must resolve a non-empty `sub` claim or signing throws a 500.

### Encrypted claims

`src/auth/encrypted-claims.ts` holds **both halves** of the encrypted-claim feature — `encryptClaims`
(used by the issuing service) and `decryptClaims` (used by verification) — because they must agree
exactly on the JWE header and key encoding. It lives under `src/auth/` and respects that
directory's import boundary (only `jose` + node builtins), so the server imports *from* it and not
the reverse.

The blob is a compact JWE, `alg: dir` + `enc: A256GCM`, under a 32-byte shared key supplied as
base64 or hex; short passphrases are rejected rather than stretched. On the issuing side
`TokenWeaverService` parses each strategy's key once in its constructor and `addEncryptedClaims`
maps + encrypts the block just before signing, so `jwt.service.ts` needs no knowledge of it. On the
verification side `buildDecryptor` in `auth.core.ts` runs after signature verification and **before**
authorization, replacing the ciphertext string in the returned payload with the decrypted object;
`requirements`/`paths` still read top-level claims only. Config validation rejects a blob claim that
is reserved (`iss`/`iat`/`exp`/`sub`) or collides with a mapped public claim.

### Published library: auth-verification middleware (`src/auth/`)

This repo is **both an app and a library**. `src/auth/` is a separate, server-independent
entry that publishes a configurable JWT-*verification* Express middleware
(`createAuthMiddleware`) so downstream services don't reimplement token validation. It is
exposed via the `./auth` subpath in `package.json` `exports` and consumed as
`import { createAuthMiddleware } from 'token-weaver/auth'`.

Hard boundary: `src/auth/` imports **only** `jose` + Express types — never the server,
controllers, services, strategies, or config. Importing the library must not pull the server
into a consumer's module graph. Three modes (`jwt-jwks`/RS256, `jwt-hs256`/HS256, `static`); on
success it sets `req.jwtPayload` and calls an optional `onVerified` hook, on failure it passes
a neutral `AuthError` (status 401) to `next()`. See `README.md` for the consumer API.

It also does **optional, opt-in authorization** (ported from `ipb-nexus`): `requirements`
(`scope`/`claim_includes`) and `paths` (whitelist/blacklist patterns read from token claims, with
`pathPrefix` stripping). Authorization failures pass a `ForbiddenError` (status **403**, distinct
from the 401 `AuthError`); `static` mode skips authorization. The allow/deny patterns live in the
JWT claims — Token Weaver's issuing strategies already emit arbitrary claims, so this is purely a
verification-side feature (no issuing change). `createAuthMiddlewareFromEnv()` (in `src/auth/env.ts`)
builds the same middleware from `AUTH_*` env vars. All of this is additive: with no
`requirements`/`paths`, behavior is unchanged.

This dual purpose splits the build (see Conventions): `build:lib` (`tsconfig.lib.json`) compiles
**only `src/auth/**`** for consumers — keeping the server and its `logra` dependency out of the
published bundle — while `build` (`tsconfig.build.json`) compiles the full server. A `prepare`
guard runs `build:lib` on git-install without breaking the Docker `npm ci`.

### Cross-cutting middleware (`src/middlewares/`)

`requestContextMiddleware` attaches a request id used by the `logra` logger (`src/utils/logger.ts`); `errorHandlerMiddleware` maps `HttpError`/`UpstreamUnavailableError` (`src/utils/http-error.ts`) to responses — upstream failures/timeouts become `503`, credential failures `401`; `authRateLimitMiddleware` is mounted on `/auth` only when `RATE_LIMIT_ENABLED=true` (in-process limiter — replace with a shared store if scaling horizontally). `setupShutdown` (`src/utils/shutdown.ts`) drains in-flight requests on SIGTERM/SIGINT.

## Conventions and gotchas

- **ESM build fix:** TypeScript emits extensionless relative imports that Node's ESM loader rejects, so `npm run build` runs `scripts/fix-dist-esm-imports.js` over `dist/` to append `.js`. Don't remove this step.
- **Library packaging (app + lib in one `package.json`):** two builds share the `rootDir: "."` trick (so output stays at `dist/src/...` — the Dockerfile runs `dist/src/index.js`; `declaration: true`; excludes `tests`):
  - `build` (`tsconfig.build.json`, `include: src/**`) — **full server**, used by the Docker image / `npm start`.
  - `build:lib` (`tsconfig.lib.json`, `include: src/auth/**`) — **library only**. Compiling the whole server for a consumer would pull in `logra` (a server-only git dep) and fail on a clean install (`TS2307`); `src/auth/**` imports only `jose` + express types + node builtins, so `build:lib` builds in isolation.
  - `prepare` is an **inline shell guard** — `if [ -d src ]; then npm run build:lib; fi` — so a git-install builds the lib itself, while the Docker `npm ci` (which runs before `COPY . .`, with no `src/`) skips cleanly. Do **not** move this guard into a `scripts/*.js` file (not copied yet at `npm ci` time → `Cannot find module`) and do **not** add `--ignore-scripts` to the Dockerfile (it would also suppress the `logra` git-dep's own `prepare`).
- `"type": "module"` — this is an ESM project; use `import`, not `require`.
- Config values support `${ENV_VAR}` placeholders, resolved recursively at load time (`resolveDeep` in `token-weaver.config.ts`); a referenced env var that is unset throws on startup. Use this for secrets rather than inlining them in YAML.
- `config/keys/` and `config/token-weaver.yaml` are local-only (gitignored); only the `.example` files are tracked.
- Strategy `name`s must be unique and cannot be `health` or `.well-known` (reserved; enforced by the config schema).
- The `audit` skill expects `docs/project-audit-rules.md` — that file is not present yet; only `docs/shared-auth-middleware.md` exists.
