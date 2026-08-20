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

### JWT (token exchange)

Verifies a JWT issued by somebody else - an identity provider, another gateway - against their
JWKS, then issues one of yours built from its claims.

Use this when you want to control what YOUR token says. Consumers trust one issuer and one claim
vocabulary; upstream identity providers can change behind it, because their claims are mapped
here rather than taught to every consumer. Verification happens in-process, so unlike a
`delegated` strategy pointed at an introspection endpoint there is no network hop per exchange
(the JWKS itself is fetched and cached once).

```yaml
strategies:
  - name: ipb
    type: jwt
    # Where the inbound token is. Defaults to the Authorization header; 'Bearer ' is tolerated.
    credential_path: $.request.headers.authorization
    verify:
      jwks_uri: https://idp.example.com/.well-known/jwks.json
      issuer: https://idp.example.com/
      audience: ipb                     # optional
      requirements:                     # optional - claims the inbound token must carry
        - { type: scope, value: 'ipb:play' }
    claims:
      # The verified upstream payload is at $.request.jwt
      sub: $.request.jwt.sub
      email: $.request.jwt.email
      # ...alongside anything you want to assert yourself
      routes:
        whitelist: ['ipb/v1/getPlayerState']
    jwt:
      algorithm: RS256
      issuer: token-weaver
      ttl: 600
```

Only mapped claims are carried over - an upstream `scope` (or anything else) does **not** appear
in the issued token unless the mapping says so.

#### Per-client claim sets on one endpoint

A `jwt` strategy can issue different claims depending on which client is calling, so a kiosk
build and a mobile app share one URL instead of needing a strategy each:

```yaml
    claims:                       # base, for every client
      sub: $.request.jwt.sub
    client_id_path: $.request.body.clientId   # default
    clients:
      - client_id: kiosk-a1b2
        claims:
          routes: { whitelist: ['ipb/v1/getPlayerState'] }
      - client_id: mobile-c3d4
        claims:
          routes: { whitelist: ['ipb/v1/*'] }
```

A matched entry's claims are layered over the base **per top-level claim** - a client that maps
`routes` replaces the base `routes` outright rather than being deep-merged into it, so a client's
permissions read exactly as written.

An unknown or absent identifier is refused with 401. Set `require_known_client: false` to fall
back to the base claims instead, when those are a deliberate public tier.

**The identifier is supplied by the caller**, so on its own it lets a client choose its own claim
set - it is only as strong as its secrecy. For anything beyond internal use, set `client_claim`
to the name of a verified claim on the inbound token that must agree with the identifier (equal,
or containing it when the claim is an array):

```yaml
    client_claim: client_ids
```

With that, the upstream token authorizes which clients the caller may present, and the identifier
only selects among sets that token already permits. A mismatch is a **403** - the token is valid,
it just does not authorize that client - as distinct from the 401 an unverifiable token gets. Failures distinguish the two cases a caller
cares about: **401** when the token cannot be verified (bad signature, wrong issuer or audience,
expired) and **403** when it verifies but does not satisfy `requirements`. `encrypted_claims`
works the same as for other strategies.

### Custom (operator-supplied module)

For login logic too specific to express as `direct` credentials or a `delegated` HTTP call —
project rules, several upstreams consulted together, a bespoke signature scheme. A JavaScript
module you bind into the container decides the outcome; Token Weaver still signs the token, so
`jwt` and `encrypted_claims` work exactly as for any other strategy.

```yaml
strategies:
  - name: custom-login
    type: custom
    handler: /app/custom/custom-login.mjs   # loaded at STARTUP
    # handler_export: authenticate          # default: `default`, falling back to `authenticate`
    timeout_ms: 5000                        # default 5000
    options:                                # handed to the handler, so the module stays env-agnostic
      profileUrl: https://profiles.example.com/lookup
      tier: standard
    claims:                                 # optional BASE claims, merged under the handler's
      audience: internal                    # plain strings are literals; `$…` is a path
      # sub: $.handler.profile.id           # $.handler is the handler's returned object
    jwt:
      algorithm: RS256
      issuer: token-weaver
      ttl: 3600
```

The handler contract — see `examples/custom-login.mjs` for a worked example:

| Handler does | Result |
|---|---|
| returns claims, or `{ claims }` | minted into the token |
| returns `null`/`undefined` | **401** |
| throws with a numeric `.status` (use the injected `HttpError`) | that status — pick 400, 403, 429... |
| throws anything else | **500**, logged with the strategy name |
| returns a non-object | **500**, logged |
| exceeds `timeout_ms` | **503** |

A thrown bug is deliberately **not** a 401: a broken handler must not be reported to callers as
bad credentials. The timeout is 503 rather than 504 because the shared error middleware passes 4xx
and 503 through and collapses other 5xx to a bare 500.

#### Claims from the config, the handler, or both

The handler does **not** have to produce every claim. `claims` in the config is a **base**, and
what the handler returns is layered over it **per top-level claim** — so a deployment can pin
claims in config while the handler supplies only the per-login parts:

```yaml
    claims:
      audience: internal             # plain strings are literals
      tier: standard
      env: $.request.headers.x-env   # `$…` is a path: $.request.* or $.handler.*
```

```js
export default async ({ request }) => ({ sub: await resolveId(request), tier: 'premium' });
// minted: audience=internal, env=…, sub=…, tier=premium   (handler wins the tier conflict)
```

The handler wins a conflict — both are deployment code, and the value closer to the request is the
useful one. To keep a claim under config's control, don't return it from the handler.

One wrinkle: `$.handler` lets config derive claims from the handler's result (e.g.
`sub: $.handler.profile.id`), but the handler's own keys are still layered in, so `profile` would
be minted too. When that matters, return the final shape from the handler — it's code, so shaping
there is the natural place.

Handlers receive `{ request, options, logger, httpRequest, HttpError }`, where `request` is shaped
exactly as the `$.request.*` mapping expressions see it. ESM and CommonJS modules both load.

The injected `logger` is Token Weaver's own [logra](https://github.com/GiganticPlayground/logra)
logger, so app logs need no imports and inherit the service's level and format. A handler can also
import `logra` (or `jose`, `yaml`, `zod`, ...) directly to make its own named logger:

```js
import { createLogger, LOG_TYPES } from 'logra';

const log = createLogger('custom-login', { style: LOG_TYPES.PRETTY });

export default async function authenticate({ request }) {
  log.info('resolving profile', { user: request.body?.username });
  ...
}
```

**Imports only resolve when the handler is mounted under the app directory** (e.g.
`/app/custom/…`), because node resolves `node_modules` by walking up from the module. A handler
outside it that imports anything fails at startup with `Cannot find package 'logra'` — the error
says so, and the container exits rather than serving.

**This is arbitrary code running in-process with the service's privileges** — deployment code, not
user input. Whoever can set `handler` can already set the signing key. The module is imported
during startup, so a missing file, a syntax error or a wrong export name fails the container
rather than surfacing as 500s on a login later.

## Endpoints

- `POST /auth/{name}`
- `GET /.well-known/jwks.json`
- `GET /health`
- `GET /api-docs` — Swagger UI _(disabled when `API_DOCS_ENABLED=false`)_
- `GET /api-docs.yaml` — the OpenAPI document itself, for another docs site, codegen or a
  contract test to fetch _(disabled with the same flag)_

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
- `encrypted_claims`: optional block of claims encrypted into one opaque JWT claim (see below)
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

### Encrypted Claims (confidential from the frontend)

A JWT is signed, not encrypted — anything in its payload is readable by whoever holds the token,
including a browser. To carry claims the frontend must **not** read (internal ids, price tiers,
entitlements), add an `encrypted_claims` block to any strategy. Its claims are mapped exactly like
public `claims`, then encrypted into a **compact JWE** stored as one opaque claim of the normal
signed JWT. Backends holding the shared secret decrypt it; everyone else sees ciphertext.

```yaml
- name: player
  type: delegated
  # ... upstream / response_mapping as usual ...
  response_mapping:
    claims:                             # readable by anyone holding the token
      sub: $.response.body.userId
      scope: [general]
  encrypted_claims:
    secret: ${TW_ENC_SECRET}            # 32-byte key: openssl rand -base64 32
    claim: enc                          # claim carrying the blob (default `enc`)
    kid: enc-key-1                      # optional; written to the JWE header
    claims:                             # readable ONLY with the shared secret
      internalUserId: $.response.body.internalId
      entitlements: $.response.body.entitlements
```

The issued token looks like a normal JWT with one extra opaque claim:

```json
{ "sub": "player-123", "scope": ["general"], "enc": "eyJhbGciOiJkaXIi...", "iss": "...", "exp": 1 }
```

Fields:

| Field | Required | Meaning |
| --- | --- | --- |
| `secret` | yes | Shared key: 32 bytes, base64 or hex. Passphrases are rejected, not stretched. Use `${ENV_VAR}`. |
| `claims` | yes | Claims to encrypt. Same `$` path mapping as public claims. |
| `claim` | no | Claim name carrying the blob. Default `enc`. Cannot be `iss`/`iat`/`exp`/`sub`, or collide with a mapped public claim (both rejected at startup). |
| `kid` | no | Key id written to the JWE protected header, so a consumer can tell which key to use. |

The blob is `alg: dir` + `enc: A256GCM` (direct AES-256-GCM under the shared key) in standard
RFC 7516 compact form, so a consumer in any language can decrypt it. From Node, use the
verification middleware's `encryptedClaims` option (below) or the exported `decryptClaims`.

Security notes:
- This adds **confidentiality from the token holder**, not integrity — the outer JWT signature
  already covers the blob, and GCM makes tampering fail decryption.
- Anyone with the secret can decrypt, so use **one secret per audience** rather than one
  deployment-wide key. Each strategy configures its own.
- `sub` must stay a public claim (signing requires it), and each blob adds roughly 100 bytes plus
  its ciphertext to the token — keep the block small enough for a header.
- The secret is validated at startup: a wrong-length key fails fast, not on first request.

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
| `API_DOCS_ENABLED` | `true` | Mounts the Swagger UI at `/api-docs` and the raw spec at `/api-docs.yaml`; set to `false` to disable both in production |
| `SHUTDOWN_TIMEOUT_MS` | `30000` | Maximum time in milliseconds to wait for in-flight requests to complete on SIGTERM/SIGINT before force-exiting |
| `REQCAST_CONFIG` | — | Path to a [reqcast](https://github.com/GiganticPlayground/reqcast) request-analytics config, YAML or JSON; falls back to the first of `./reqcast.config.json`, `./reqcast.config.yaml`, `./reqcast.config.yml` that exists, otherwise analytics stay disabled (see `examples/reqcast.config.json`) |

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
    mode: 'jwt-jwks',
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

Three modes (a single instance uses one; combine several via `strategies` — see below):

| Mode | Verifies | Required options |
| --- | --- | --- |
| `jwt-jwks` | RS256 JWT against a remote JWKS | `issuer`, `jwksUri` |
| `jwt-hs256` | HS256 JWT against a shared secret | `issuer`, `secret` |
| `static` | constant-time compare of the bearer to a fixed token | `staticToken` |

Behavior:
- Reads `Authorization: Bearer <token>`; missing/malformed → `401`.
- On success attaches the decoded payload to `req.jwtPayload` and awaits the optional
  `onVerified(payload, req)` hook, then calls `next()`. For `static` mode the payload is `{}`.
- On any failure (expired, bad signature, wrong issuer/audience, missing token) it calls
  `next(err)` with a framework-neutral `AuthError` carrying `status: 401`, so your own
  error middleware renders the response.
- Options are validated at construction time and **fail fast** on an inconsistent combination.

### Multiple strategies (accept more than one at once)

Instead of a single strategy, pass a **`strategies`** array. Each entry is a full single-strategy
option object (its own `mode`, keys, `requirements`, `paths`). Incoming requests are tried against
each strategy **in order** and the **first that accepts wins**; the shared `onVerified` then runs
once for the winner. If every strategy rejects, the most informative failure is surfaced — a `403`
(authenticated but not authorized) is preferred over a `401`.

This lets one deployment accept several token schemes simultaneously — e.g. an internal static
service token **and** client JWTs:

```ts
createAuthMiddleware({
  strategies: [
    { mode: 'static', staticToken: process.env.INTERNAL_TOKEN,
      paths: { whitelist: ['/qodi/decrypt'] } },       // internal service: decrypt only
    { mode: 'jwt-jwks', issuer: 'token-weaver',
      jwksUri: process.env.JWKS_URL },                  // clients: token-weaver JWTs
  ],
  onVerified: (payload, req) => { req.auth = { userId: payload.sub }; },
});
```

### Optional authorization (requirements & path allow/deny)

Beyond authenticating the token, the middleware can optionally **authorize** the request. These
are opt-in — omit them and the middleware only authenticates. Authorization failures pass a
`ForbiddenError` (status `403`) to `next()`. The model: **Token Weaver defines access by embedding
claims when it issues the JWT, and the middleware enforces them.**

`requirements` are claim-based, so they are skipped in `static` mode. `paths` supports two pattern
sources: **claim-based** (`whitelistClaim`/`blacklistClaim`, JWT modes only) and **inline**
(`whitelist`/`blacklist` arrays, declared in config). Inline patterns need no claims, so they are
the way to scope a **`static`** token to specific paths:

```ts
createAuthMiddleware({
  mode: 'static',
  staticToken: process.env.INTERNAL_TOKEN,
  paths: { whitelist: ['/qodi/decrypt'] },  // this static token may ONLY hit /qodi/decrypt
});
```

```ts
createAuthMiddleware({
  mode: 'jwt-jwks',
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

### Decrypting encrypted claims

When the issuing strategy uses `encrypted_claims` (above), give the middleware the matching
secret. After verification the blob claim on `req.jwtPayload` holds the **decrypted object**
instead of the ciphertext string:

```ts
createAuthMiddleware({
  mode: 'jwt-jwks',
  issuer: 'https://token-weaver.example.com',
  jwksUri: 'https://token-weaver.example.com/.well-known/jwks.json',
  encryptedClaims: {
    secret: process.env.TW_ENC_SECRET,  // 32-byte key, base64 or hex
    claim: 'enc',                       // default 'enc'
    required: true,                     // default true
  },
  onVerified: (payload, req) => {
    req.auth = { userId: payload.sub, ...readEncryptedClaims(payload) };
  },
});
```

Behavior:
- A missing blob is a `401` when `required` (the default); set `required: false` to accept tokens
  that carry no blob. A blob that **is** present but fails to decrypt is always a `401`.
- Decryption runs **after** signature verification and **before** authorization. Note that
  `requirements`/`paths` read **top-level** claims, so a scope or path list hidden inside the blob
  does not satisfy them — keep access-control claims public and secrets in the blob.
- `secret` accepts an **array** to support rotation: keys are tried in order, so a consumer can
  accept the previous key while issuers roll onto the new one.
- Malformed secrets throw at construction time (fail fast), like the other options.
- Ignored in `static` mode, which has no claims.

For flows outside the middleware, the same helpers are exported directly:

```ts
import { decryptClaims, encryptClaims, parseEncryptionKey } from 'token-weaver/auth';

const key = parseEncryptionKey(process.env.TW_ENC_SECRET);   // validates the 32-byte length
const claims = await decryptClaims(payload.enc, [key]);
```

### Configuring from environment variables

`createAuthMiddlewareFromEnv()` builds the same middleware from environment variables instead of
an inline options object. The variables are read from `process.env` **once, at the time you call
the factory** (typically at startup), so make sure they're loaded first — the consuming app is
responsible for populating its own environment (e.g. via its process manager, container env, or
its own `dotenv` setup; this library does not call `dotenv`).

```ts
import { createAuthMiddlewareFromEnv } from 'token-weaver/auth';

// Reads AUTH_* from process.env and fails fast if the combination is invalid.
app.use(createAuthMiddlewareFromEnv());
```

Pass `{ prefix, env, onVerified }` to override: `prefix` changes the `AUTH_` namespace (so several
instances can coexist), `env` supplies an alternative source object, and `onVerified` is the
post-verification hook (it can't be expressed as a string env var).

```ts
// Two independent gates from one process, plus a claim-mapping hook:
app.use('/public', createAuthMiddlewareFromEnv({ prefix: 'PUBLIC_AUTH_' }));
app.use('/admin', createAuthMiddlewareFromEnv({
  prefix: 'ADMIN_AUTH_',
  onVerified: (payload, req) => { req.userId = payload.sub; },
}));
```

| Env var (prefix `AUTH_`) | Maps to | Notes |
| --- | --- | --- |
| `AUTH_MODE` | `mode` | `jwt-jwks` \| `jwt-hs256` \| `static` |
| `AUTH_ISSUER` | `issuer` | required for jwt modes |
| `AUTH_AUDIENCE` | `audience` | optional |
| `AUTH_JWKS_URI` | `jwksUri` | `jwt-jwks` mode |
| `AUTH_SECRET` | `secret` | `jwt-hs256` mode |
| `AUTH_STATIC_TOKEN` | `staticToken` | `static` mode |
| `AUTH_PATH_PREFIX` | `paths.pathPrefix` | optional |
| `AUTH_WHITELIST_CLAIM` | `paths.whitelistClaim` | optional; enables `paths` |
| `AUTH_BLACKLIST_CLAIM` | `paths.blacklistClaim` | optional; enables `paths` |
| `AUTH_REQUIREMENTS` | `requirements` | JSON array, e.g. `[{"type":"scope","value":"nexus:read"}]` |
| `AUTH_ENC_SECRET` | `encryptedClaims.secret` | optional; enables blob decryption. Comma-separated for rotation |
| `AUTH_ENC_CLAIM` | `encryptedClaims.claim` | optional; default `enc` |
| `AUTH_ENC_REQUIRED` | `encryptedClaims.required` | optional; `false` makes the blob optional |

Empty strings are treated as unset. Worked examples:

```bash
# JWKS / RS256 — verify against Token Weaver's published keys, with path allow/deny + a scope gate
AUTH_MODE=jwt-jwks
AUTH_ISSUER=https://token-weaver.example.com
AUTH_JWKS_URI=https://token-weaver.example.com/.well-known/jwks.json
AUTH_AUDIENCE=my-service                 # optional
AUTH_WHITELIST_CLAIM=whitelist           # read allowed path patterns from this token claim
AUTH_BLACKLIST_CLAIM=blacklist           # blacklist wins over whitelist
AUTH_PATH_PREFIX=/api                    # stripped from the request path before matching
AUTH_REQUIREMENTS=[{"type":"scope","value":"nexus:read"}]
```

```bash
# HS256 — shared secret
AUTH_MODE=jwt-hs256
AUTH_ISSUER=https://token-weaver.example.com
AUTH_SECRET=${JWT_SHARED_SECRET}
```

```bash
# Static bearer token — service-to-service without a JWT issuer
AUTH_MODE=static
AUTH_STATIC_TOKEN=${SERVICE_TOKEN}
```

### Library install notes

- The package builds itself on install via a `prepare` script (no committed `dist/`).
  `prepare` runs `build:lib`, which compiles **only `src/auth/**`** (via `tsconfig.lib.json`)
  — so a consumer install never needs the server's deps (e.g. `logra`). `npm run build`
  remains the **full server** build used by Token Weaver's own Docker image / `npm start`.
- An **incremental** `npm/yarn add` in a consumer may skip `prepare` and leave `dist/`
  empty; the fallback is `tsc -p node_modules/token-weaver/tsconfig.lib.json` (the lib-only
  build — **not** `tsconfig.build.json`, which would try to compile the server and fail).
- `express` is a peer dependency (`^5`); the consumer provides it.
- The emitted `.d.ts` use extensionless relative imports, which resolve under
  `moduleResolution: bundler`/`node16` typings; a strict `nodenext` consumer may need attention.

## Implementation Layout

- [src/controllers/authController.ts](/Users/daniellmorris/work/gigaplay/os/token-weaver/src/controllers/authController.ts): auth and JWKS endpoints
- [src/services/token-weaver.service.ts](/Users/daniellmorris/work/gigaplay/os/token-weaver/src/services/token-weaver.service.ts): strategy execution and request orchestration
- [src/services/jwt.service.ts](/Users/daniellmorris/work/gigaplay/os/token-weaver/src/services/jwt.service.ts): JWT signing and JWKS generation
- [src/config/token-weaver.config.ts](/Users/daniellmorris/work/gigaplay/os/token-weaver/src/config/token-weaver.config.ts): strategy config loading and validation
- [src/utils/path-expression.ts](/Users/daniellmorris/work/gigaplay/os/token-weaver/src/utils/path-expression.ts): path resolution and simple condition evaluation for mappings
- [src/auth/encrypted-claims.ts](/Users/daniellmorris/work/gigaplay/os/token-weaver/src/auth/encrypted-claims.ts): encrypted claim blobs — both the issuing and verification halves

## Notes

- `/auth/{name}` is protected by a simple in-process rate limit of 30 requests per minute per client IP
- if the service is scaled across multiple instances, replace this with a shared-store distributed limiter such as Redis-backed rate limiting
- Upstream failures and timeouts return `503`
- credential failures return `401`
- the service fails at startup if signing key material is unavailable
