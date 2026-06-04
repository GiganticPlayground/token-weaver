# Token Weaver

Token Weaver is a configurable authentication gateway that accepts inbound credentials, applies a configured strategy, and returns a signed JWT on success.

It is intentionally narrow in scope:
- Token Weaver issues JWTs
- downstream services validate JWTs
- Token Weaver does not require a downstream user record to exist before issuing a token

## Supported Strategies

### Direct

Matches a configured credential locally and translates it directly into JWT claims. No upstream call is made.

Use this for:
- machine-to-machine clients
- static device credentials
- bounded client sets known at deploy time

### Delegated

Transforms the inbound request, forwards it to an upstream HTTP service, evaluates the upstream response, and issues a JWT if the configured success condition passes.

Use this for:
- existing external auth systems
- player or account systems that decide authentication dynamically
- flows where the subject record may not exist until the upstream system handles the request

## Endpoints

- `POST /auth/{name}`
- `GET /.well-known/jwks.json`
- `GET /health`
- `GET /api-docs` _(disabled when `API_DOCS_ENABLED=false`)_

Routes are bound through the OpenAPI spec in [api/openapi.yaml](/Users/daniellmorris/work/gigaplay/os/token-weaver/api/openapi.yaml) via `express-openapi-validator`.

## Quick Start

### 1. Install dependencies

```bash
npm install
```

### 2. Create config

```bash
mkdir -p config
cp config/token-weaver.yaml.example config/token-weaver.yaml
```

### 3. Provide a signing key

Generate a local keypair:

```bash
npm run gen:keys
```

Set one of:
- `TOKEN_WEAVER_PRIVATE_KEY`
- `TOKEN_WEAVER_PRIVATE_KEY_PATH`

The key must be an RSA private key in PEM format.

### 4. Run locally

```bash
npm run dev
```

## Configuration

Token Weaver loads strategy config from:
- `TOKEN_WEAVER_CONFIG_PATH`
- default: `config/token-weaver.yaml`

Example files are provided at:
- [config/token-weaver.yaml.example](/Users/daniellmorris/work/gigaplay/os/token-weaver/config/token-weaver.yaml.example)

Core config concepts:
- `type`: `direct` or `delegated`
- `name`: unique strategy identifier and the `{name}` segment used in `POST /auth/{name}`
- `inbound_auth`: optional `api_key`, `bearer`, or `none` gate applied before strategy execution
- `credentials`: direct-strategy credential list
- `upstream`: delegated-strategy target, auth, timeout, and request mapping
- `response_mapping`: delegated-strategy success condition, error mappings, and claim extraction
- `log`: delegated-strategy optional HTTP logging flags (`request_body`, `response_body`, `request_headers`)
- `jwt`: issuer and TTL for tokens issued by that strategy

### Mapping Expressions

Token Weaver uses simple `$` path expressions to pull values out of the request or an upstream response.

Examples:
- `$.request.body.username`
- `$.request.headers.authorization`
- `$.response.body.userId`
- `$.response.status`

Array indexes and quoted keys are also supported:
- `$.request.body.roles[0]`
- `$['response']['body']['userId']`

### Direct Strategy Claims Mapping

Direct strategies match a credential locally, then copy the configured `claims` object into the JWT payload.

Example:

```yaml
credential_path: $.request.body.secret
credentials:
  - secret: ${STATIC_CLIENT_SECRET}
    claims:
      sub: client-device-001
      scope:
        - general
      customClaim: example-value
```

In that example:
- the inbound credential is read from `request.body.secret`
- if it matches, the JWT gets `sub`, `scope`, and `customClaim` exactly as configured

### Delegated Upstream Mapping

Delegated strategies can build an upstream request from the inbound request using `body_mapping` and `header_mapping`.

Example:

```yaml
upstream:
  url: https://auth-service.example.com/v1/verify
  method: POST
  header_mapping:
    X-Forwarded-User: $.request.body.username
  body_mapping:
    username: $.request.body.username
    password: $.request.body.password
```

In that example:
- the upstream JSON body is constructed from the incoming request body
- any mapped header values must resolve to a string, number, or boolean to be sent upstream

### Upstream Success, Error Mapping, And Claims Extraction

After the upstream call completes, Token Weaver evaluates `response_mapping.success_condition`. If it passes, it maps `response_mapping.claims` into the JWT payload.

If the success condition fails, `error_mappings` are evaluated in order — the first matching entry determines the HTTP status and message returned to the caller. An entry with no `condition` acts as a catch-all. If no mapping matches, the request fails with `401`.

Example:

```yaml
response_mapping:
  success_condition: $.status == 'ok'
  error_mappings:
    - condition: $.response.status == 403
      status: 403
      message: $.response.body.message   # path expression resolved from upstream response
      code: FORBIDDEN
    - condition: $.response.status == 401
      status: 401
      message: Invalid credentials        # literal string
    - status: 401                         # no condition — catch-all
      message: $.response.body.error
  claims:
    sub: $.response.body.userId
    scope:
      - general
```

In that example:
- `success_condition` checks the upstream response body field `status`
- if the condition is truthy, `sub` is copied from `response.body.userId`
- if it fails, `error_mappings` are checked in order; `message` can be a literal or a `$` path expression resolved from the upstream response
- mapped claims must resolve to an object, otherwise the request fails with a server error

### Upstream Logging

Delegated strategies accept an optional `log` block controlling what is included in upstream HTTP log entries:

```yaml
log:
  request_body: false     # include outbound request body in START - HTTP log
  response_body: false    # include upstream response body in END - HTTP log
  request_headers: false  # include outbound request headers in START - HTTP log
```

All flags default to `false`. Enable selectively for debugging — request headers may contain auth credentials.

## Environment Variables

| Variable | Default | Used for |
| --- | --- | --- |
| `PORT` | `3000` | HTTP port for the Express server |
| `NODE_ENV` | `development` | Application environment mode |
| `LOG_LEVEL` | `debug` | Minimum log level for the `logra` logger |
| `LOG_TYPE` | `pretty` | Logger output style: `pretty`, `json`, or `hidden` |
| `CORS_ORIGINS` | unset | Allowed CORS origins; unset or `*` allows all |
| `TRUST_PROXY` | `false` | Express trust proxy setting for forwarded headers and client IP handling |
| `RATE_LIMIT_ENABLED` | `false` | Enables IP-based auth endpoint rate limiting |
| `RATE_LIMIT_MAX` | `30` | Maximum auth requests per window per client IP when rate limiting is enabled |
| `RATE_LIMIT_WINDOW_MS` | `60000` | Rate-limit window length in milliseconds |
| `TOKEN_WEAVER_CONFIG_PATH` | `config/token-weaver.yaml` | Path to the Token Weaver YAML or JSON strategy config |
| `TOKEN_WEAVER_PRIVATE_KEY_PATH` | unset | Filesystem path to the RSA private key PEM used for signing JWTs |
| `TOKEN_WEAVER_PRIVATE_KEY` | unset | Inline RSA private key PEM content used for signing JWTs |
| `TOKEN_WEAVER_KID` | `token-weaver-key` | JWKS key ID included in signed JWT headers and JWKS output |
| `API_DOCS_ENABLED` | `true` | Mounts the Swagger UI at `/api-docs`; set to `false` to disable in production |
| `SHUTDOWN_TIMEOUT_MS` | `30000` | Maximum time in milliseconds to wait for in-flight requests to complete on SIGTERM/SIGINT before force-exiting |

## Development

Useful commands:

```bash
npm run dev
npm run gen:keys
npm run type-check
npm run lint
npm run format:check
npm run validate
```

## Auth Verification Middleware (library)

Token Weaver **issues** JWTs; downstream services **verify** them. The verification
logic is also published as a small, framework-light Express middleware so consumers
don't reimplement it. It is exposed on a dedicated subpath that pulls in only `jose`
— importing it does **not** load the Token Weaver server or its dependencies.

```bash
npm install github:GiganticPlayground/token-weaver#semver:^1.0.0
```

```ts
import { createAuthMiddleware } from 'token-weaver/auth';

// JWKS / RS256 (verifies against the issuer's published keys)
app.use(
  createAuthMiddleware({
    mode: 'jwks',
    issuer: 'https://token-weaver.example.com',
    jwksUri: 'https://token-weaver.example.com/.well-known/jwks.json',
    audience: 'my-service', // optional
    onVerified: (payload, req) => {
      // Map claims onto your own request shape; the lib stays consumer-agnostic.
      req.auth = { userId: payload.sub };
    },
  }),
);
```

Three modes, exactly one per instance:

| Mode | Verifies | Required options |
| --- | --- | --- |
| `jwks` | RS256 JWT against a remote JWKS | `issuer`, `jwksUri` |
| `secret` | HS256 JWT against a shared secret | `issuer`, `secret` |
| `static` | constant-time compare of the bearer to a fixed token | `staticToken` |

Behavior:
- Reads `Authorization: Bearer <token>`; missing/malformed → `401`.
- On success attaches the decoded payload to `req.jwtPayload` and awaits the optional
  `onVerified(payload, req)` hook, then calls `next()`. For `static` mode the payload is `{}`.
- On any failure (expired, bad signature, wrong issuer/audience, missing token) it calls
  `next(err)` with a framework-neutral `AuthError` carrying `status: 401`, so your own
  error middleware renders the response.
- Options are validated at construction time and **fail fast** on an inconsistent combination.

### Optional authorization (requirements & path allow/deny)

Beyond authenticating the token, the middleware can optionally **authorize** the request against
the token's own claims. These are opt-in — omit them and the middleware only authenticates.
Authorization failures pass a `ForbiddenError` (status `403`) to `next()`; `static` mode skips
authorization (no claims). The model: **Token Weaver defines access by embedding claims when it
issues the JWT, and the middleware enforces them.**

```ts
createAuthMiddleware({
  mode: 'jwks',
  issuer: 'https://token-weaver.example.com',
  jwksUri: 'https://token-weaver.example.com/.well-known/jwks.json',
  // every requirement must hold, or 403:
  requirements: [
    { type: 'scope', value: 'nexus:read' },                       // token.scope must include it
    { type: 'claim_includes', claim: 'permissions', value: 'data:read' },
  ],
  // per-endpoint allow/deny, with the patterns carried in the token's claims:
  paths: {
    pathPrefix: '/api',        // stripped from req.baseUrl+req.path before matching
    whitelistClaim: 'whitelist', // if present on the token, one pattern must match (glob * supported)
    blacklistClaim: 'blacklist', // any match denies — blacklist wins over whitelist
  },
});
```

A Token Weaver strategy issues those claims like any other (see Direct/Delegated claims mapping):

```yaml
claims:
  sub: $.response.body.userId
  scope:
    - nexus:read
  whitelist:
    - /nexus/*
```

### Configuring from environment variables

`createAuthMiddlewareFromEnv()` builds the same middleware from env vars (default prefix `AUTH_`;
pass `{ prefix, env, onVerified }` to override). Mode-specific required fields are still validated
fail-fast.

```ts
import { createAuthMiddlewareFromEnv } from 'token-weaver/auth';
app.use(createAuthMiddlewareFromEnv());
```

| Env var (prefix `AUTH_`) | Maps to | Notes |
| --- | --- | --- |
| `AUTH_MODE` | `mode` | `jwks` \| `secret` \| `static` |
| `AUTH_ISSUER` | `issuer` | required for jwt modes |
| `AUTH_AUDIENCE` | `audience` | optional |
| `AUTH_JWKS_URI` | `jwksUri` | `jwks` mode |
| `AUTH_SECRET` | `secret` | `secret` mode |
| `AUTH_STATIC_TOKEN` | `staticToken` | `static` mode |
| `AUTH_PATH_PREFIX` | `paths.pathPrefix` | optional |
| `AUTH_WHITELIST_CLAIM` | `paths.whitelistClaim` | optional; enables `paths` |
| `AUTH_BLACKLIST_CLAIM` | `paths.blacklistClaim` | optional; enables `paths` |
| `AUTH_REQUIREMENTS` | `requirements` | JSON array, e.g. `[{"type":"scope","value":"nexus:read"}]` |

### Library install notes

- The package builds itself on install via a `prepare` script (no committed `dist/`).
  An **incremental** `npm/yarn add` in a consumer may skip `prepare` and leave `dist/`
  empty; the fallback is `tsc -p node_modules/token-weaver/tsconfig.build.json`.
- `express` is a peer dependency (`^5`); the consumer provides it.
- The emitted `.d.ts` use extensionless relative imports, which resolve under
  `moduleResolution: bundler`/`node16` typings; a strict `nodenext` consumer may need attention.

## Implementation Layout

- [src/controllers/authController.ts](/Users/daniellmorris/work/gigaplay/os/token-weaver/src/controllers/authController.ts): auth and JWKS endpoints
- [src/services/token-weaver.service.ts](/Users/daniellmorris/work/gigaplay/os/token-weaver/src/services/token-weaver.service.ts): strategy execution and request orchestration
- [src/services/jwt.service.ts](/Users/daniellmorris/work/gigaplay/os/token-weaver/src/services/jwt.service.ts): JWT signing and JWKS generation
- [src/config/token-weaver.config.ts](/Users/daniellmorris/work/gigaplay/os/token-weaver/src/config/token-weaver.config.ts): strategy config loading and validation
- [src/utils/path-expression.ts](/Users/daniellmorris/work/gigaplay/os/token-weaver/src/utils/path-expression.ts): path resolution and simple condition evaluation for mappings

## Notes

- `/auth/{name}` is protected by a simple in-process rate limit of 30 requests per minute per client IP
- if the service is scaled across multiple instances, replace this with a shared-store distributed limiter such as Redis-backed rate limiting
- Upstream failures and timeouts return `503`
- credential failures return `401`
- the service fails at startup if signing key material is unavailable
