# Examples

## Swarm

The `swarm/` example shows a minimal Docker Compose deployment of Token Weaver using:

- a Docker config for the Token Weaver YAML
- a Docker secret for the private signing key
- a generated local RSA keypair
- a single direct strategy exposed at `POST /auth/device`

### Setup

From the repo root:

```bash
chmod +x examples/generate-keys.sh
./examples/generate-keys.sh
docker compose -f examples/swarm/docker-compose.yml up
```

### Test Request

```bash
curl -X POST http://localhost:3000/auth/device \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: dev-inbound-key' \
  -d '{"secret":"dev-swarm-secret"}'
```

The example config lives at [examples/swarm/token-weaver.yaml](/Users/daniellmorris/work/gigaplay/os/token-weaver/examples/swarm/token-weaver.yaml), and generated keys are written to `examples/swarm/keys/`. The compose file exposes that YAML as a Docker config and the private key PEM as a Docker secret.
