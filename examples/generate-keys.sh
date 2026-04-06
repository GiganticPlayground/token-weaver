#!/usr/bin/env bash

set -euo pipefail

EXAMPLES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${EXAMPLES_DIR}/.." && pwd)"

node "${REPO_ROOT}/scripts/generate-keys.js" \
  --out-dir "${EXAMPLES_DIR}/swarm/keys" \
  --kid "token-weaver-swarm-example"
