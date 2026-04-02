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

- `POST /auth`
- `GET /.well-known/jwks.json`
- `GET /health`
- `GET /api-docs`

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

An example file is provided at [config/token-weaver.yaml.example](/Users/daniellmorris/work/gigaplay/os/token-weaver/config/token-weaver.yaml.example).

Core config concepts:
- `type`: `direct` or `delegated`
- `route`: request path and optional header/query discriminators used to select a strategy
- `inbound_auth`: optional `api_key`, `bearer`, or `none` gate applied before strategy execution
- `credentials`: direct-strategy credential list
- `upstream`: delegated-strategy target, auth, timeout, and request mapping
- `response_mapping`: delegated-strategy success condition and claim extraction
- `jwt`: issuer and TTL for tokens issued by that strategy

## Environment Variables

- `PORT`: HTTP port, default `3000`
- `NODE_ENV`: `development`, `test`, or `production`
- `TOKEN_WEAVER_CONFIG_PATH`: path to YAML or JSON strategy config
- `TOKEN_WEAVER_PRIVATE_KEY`: RSA private key PEM content
- `TOKEN_WEAVER_PRIVATE_KEY_PATH`: path to RSA private key PEM file
- `TOKEN_WEAVER_KID`: JWKS key id, default `token-weaver-key`

## Development

Useful commands:

```bash
npm run dev
npm run type-check
npm run lint
npm run format:check
npm run build
```

## Implementation Layout

- [src/controllers/authController.ts](/Users/daniellmorris/work/gigaplay/os/token-weaver/src/controllers/authController.ts): auth and JWKS endpoints
- [src/services/token-weaver.service.ts](/Users/daniellmorris/work/gigaplay/os/token-weaver/src/services/token-weaver.service.ts): strategy execution and request orchestration
- [src/services/jwt.service.ts](/Users/daniellmorris/work/gigaplay/os/token-weaver/src/services/jwt.service.ts): JWT signing and JWKS generation
- [src/config/token-weaver.config.ts](/Users/daniellmorris/work/gigaplay/os/token-weaver/src/config/token-weaver.config.ts): strategy config loading and validation
- [src/utils/path-expression.ts](/Users/daniellmorris/work/gigaplay/os/token-weaver/src/utils/path-expression.ts): path resolution and simple condition evaluation for mappings

## Notes

- Upstream failures and timeouts return `503`
- credential failures return `401`
- the service fails at startup if signing key material is unavailable
