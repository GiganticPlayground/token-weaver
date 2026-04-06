#!/usr/bin/env node

import { generateKeyPairSync } from 'crypto';
import { mkdirSync, writeFileSync } from 'fs';
import { resolve } from 'path';

const args = new Map();
for (let index = 2; index < process.argv.length; index += 1) {
  const part = process.argv[index];
  if (part.startsWith('--')) {
    args.set(part, process.argv[index + 1]);
    index += 1;
  }
}

const outDir = resolve(args.get('--out-dir') ?? 'config/keys');
const kid = args.get('--kid') ?? 'token-weaver-dev-key';
const privateKeyPath = resolve(outDir, 'private-key.pem');
const publicKeyPath = resolve(outDir, 'public-key.pem');

mkdirSync(outDir, { recursive: true });

const { privateKey, publicKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: {
    type: 'spki',
    format: 'pem',
  },
  privateKeyEncoding: {
    type: 'pkcs8',
    format: 'pem',
  },
});

writeFileSync(privateKeyPath, privateKey, 'utf8');
writeFileSync(publicKeyPath, publicKey, 'utf8');

console.log(`Generated RSA keypair:
- private key: ${privateKeyPath}
- public key: ${publicKeyPath}

Suggested environment:
TOKEN_WEAVER_PRIVATE_KEY_PATH=${privateKeyPath}
TOKEN_WEAVER_KID=${kid}`);
