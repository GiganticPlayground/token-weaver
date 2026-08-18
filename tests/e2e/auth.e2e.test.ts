import { createHmac, generateKeyPairSync } from 'crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'fs';
import assert from 'node:assert/strict';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { after, before, describe, it } from 'node:test';
import { tmpdir } from 'os';
import { join } from 'path';

import { SignJWT, exportJWK, importPKCS8, importSPKI } from 'jose';
import YAML from 'yaml';

import { compileAuth, decryptClaims, parseEncryptionKey } from '../../src/auth/index';

/** 32-byte shared key for the encrypted-claim strategies, as base64 (see parseEncryptionKey). */
const encryptionSecret = Buffer.from('token-weaver-e2e-encryption-key!').toString('base64');
const encryptionKey = parseEncryptionKey(encryptionSecret);

type TestContext = {
  serviceProcess: ChildProcessWithoutNullStreams;
  servicePort: number;
  upstreamServer: Server;
  tmpDir: string;
  output: string[];
};

const testContext = {} as TestContext;

function getJson<T>(value: string): T {
  return JSON.parse(value) as T;
}

function decodeJwtPart(part: string): Record<string, unknown> {
  return getJson<Record<string, unknown>>(Buffer.from(part, 'base64url').toString('utf8'));
}

async function getAvailablePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (!address || typeof address === 'string') {
        reject(new Error('Failed to allocate a test port'));
        return;
      }

      const { port } = address;
      server.close((error) => {
        if (error) {
          reject(error);
          return;
        }

        resolve(port);
      });
    });
  });
}

async function readJsonBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  const body = await new Promise<string>((resolve, reject) => {
    let data = '';
    req.setEncoding('utf8');
    req.on('data', (chunk: string) => {
      data += chunk;
    });
    req.on('end', () => {
      resolve(data);
    });
    req.on('error', reject);
  });

  return body ? getJson<Record<string, unknown>>(body) : {};
}

function createUpstreamHandler(expectedToken: string) {
  return (req: IncomingMessage, res: ServerResponse): void => {
    void (async () => {
      if (req.headers.authorization !== `Bearer ${expectedToken}`) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'unauthorized' }));
        return;
      }

      if (req.method !== 'POST') {
        res.writeHead(405, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'method-not-allowed' }));
        return;
      }

      const requestBody = await readJsonBody(req);
      const username = requestBody.username;
      const password = requestBody.password;

      if (req.url === '/verify-slow') {
        await new Promise((resolve) => globalThis.setTimeout(resolve, 200));
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'ok', userId: 'player-slow' }));
        return;
      }

      if (req.url === '/verify-with-errors') {
        if (requestBody.username === 'banned@example.com') {
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 'forbidden', message: 'Account suspended' }));
          return;
        }
        if (requestBody.username === 'valid@example.com' && requestBody.password === 'correct') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 'ok', userId: 'mapped-user-1' }));
          return;
        }
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'denied', message: 'Invalid credentials' }));
        return;
      }

      if (username === 'player@example.com' && password === 'correct-password') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'ok', userId: 'player-123' }));
        return;
      }

      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'denied' }));
    })().catch((error: unknown) => {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          status: 'error',
          message: error instanceof Error ? error.message : 'unknown error',
        }),
      );
    });
  };
}

async function startServer(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.listen(0, '127.0.0.1', (error?: Error) => {
      if (error) {
        reject(error);
        return;
      }

      resolve();
    });
  });
}

function getListeningPort(server: Server): number {
  const address = server.address();
  if (!address || typeof address === 'string') {
    throw new Error('Server is not listening');
  }

  return address.port;
}

async function waitForServiceReady(port: number, output: string[]): Promise<void> {
  const deadline = Date.now() + 10_000;

  while (Date.now() < deadline) {
    try {
      const response = await globalThis.fetch(`http://127.0.0.1:${port}/health`);
      if (response.ok) {
        return;
      }
    } catch {
      // Ignore startup connection errors while polling.
    }

    await new Promise((resolve) => globalThis.setTimeout(resolve, 100));
  }

  throw new Error(`Service failed to start.\n${output.join('')}`);
}

function createTestConfig(upstreamPort: number): string {
  return JSON.stringify(
    {
      strategies: [
        {
          name: 'static-client',
          type: 'direct',
          inbound_auth: {
            type: 'api_key',
            header: 'X-API-Key',
            key: '${TW_INBOUND_KEY}',
          },
          credential_path: '$.request.body.secret',
          credentials: [
            {
              secret: '${STATIC_CLIENT_SECRET}',
              claims: {
                sub: '$.request.body.deviceId',
                scope: ['general'],
                customClaim: '$.request.body.customClaim',
              },
            },
          ],
          jwt: {
            issuer: 'token-weaver',
            ttl: 3600,
          },
        },
        {
          name: 'delegated-player-auth',
          type: 'delegated',
          inbound_auth: {
            type: 'api_key',
            header: 'X-API-Key',
            key: '${TW_INBOUND_KEY}',
          },
          upstream: {
            url: `http://127.0.0.1:${upstreamPort}/verify`,
            method: 'POST',
            timeout_ms: 1_000,
            auth: {
              type: 'bearer',
              token: '${UPSTREAM_API_TOKEN}',
            },
            body_mapping: {
              username: '$.request.body.username',
              password: '$.request.body.password',
            },
          },
          response_mapping: {
            success_condition: "$.status == 'ok'",
            claims: {
              sub: '$.response.body.userId',
              scope: ['general'],
            },
          },
          jwt: {
            issuer: 'token-weaver',
            ttl: 3600,
          },
        },
        {
          name: 'delegated-timeout',
          type: 'delegated',
          inbound_auth: {
            type: 'api_key',
            header: 'X-API-Key',
            key: '${TW_INBOUND_KEY}',
          },
          upstream: {
            url: `http://127.0.0.1:${upstreamPort}/verify-slow`,
            method: 'POST',
            timeout_ms: 50,
            auth: {
              type: 'bearer',
              token: '${UPSTREAM_API_TOKEN}',
            },
            body_mapping: {
              username: '$.request.body.username',
              password: '$.request.body.password',
            },
          },
          response_mapping: {
            success_condition: "$.status == 'ok'",
            claims: {
              sub: '$.response.body.userId',
              scope: ['general'],
            },
          },
          jwt: {
            issuer: 'token-weaver',
            ttl: 3600,
          },
        },
        {
          name: 'delegated-error-mapped',
          type: 'delegated',
          inbound_auth: {
            type: 'api_key',
            header: 'X-API-Key',
            key: '${TW_INBOUND_KEY}',
          },
          upstream: {
            url: `http://127.0.0.1:${upstreamPort}/verify-with-errors`,
            method: 'POST',
            timeout_ms: 1_000,
            auth: {
              type: 'bearer',
              token: '${UPSTREAM_API_TOKEN}',
            },
            body_mapping: {
              username: '$.request.body.username',
              password: '$.request.body.password',
            },
          },
          response_mapping: {
            success_condition: "$.status == 'ok'",
            error_mappings: [
              {
                condition: '$.response.status == 403',
                status: 403,
                message: '$.response.body.message',
                code: 'FORBIDDEN',
              },
              {
                condition: '$.response.status == 401',
                status: 401,
                message: 'Invalid credentials',
              },
            ],
            claims: {
              sub: '$.response.body.userId',
              scope: ['general'],
            },
          },
          jwt: {
            issuer: 'token-weaver',
            ttl: 3600,
          },
        },
        {
          name: 'delegated-catchall',
          type: 'delegated',
          inbound_auth: {
            type: 'api_key',
            header: 'X-API-Key',
            key: '${TW_INBOUND_KEY}',
          },
          upstream: {
            url: `http://127.0.0.1:${upstreamPort}/verify-with-errors`,
            method: 'POST',
            timeout_ms: 1_000,
            auth: {
              type: 'bearer',
              token: '${UPSTREAM_API_TOKEN}',
            },
            body_mapping: {
              username: '$.request.body.username',
              password: '$.request.body.password',
            },
          },
          response_mapping: {
            success_condition: "$.status == 'ok'",
            error_mappings: [
              {
                status: 401,
                message: 'Authentication failed',
              },
            ],
            claims: {
              sub: '$.response.body.userId',
              scope: ['general'],
            },
          },
          jwt: {
            issuer: 'token-weaver',
            ttl: 3600,
          },
        },
        {
          name: 'encrypted-direct',
          type: 'direct',
          credentials: [
            {
              secret: '${STATIC_CLIENT_SECRET}',
              claims: {
                sub: '$.request.body.deviceId',
                scope: ['general'],
              },
            },
          ],
          encrypted_claims: {
            secret: '${TW_ENC_SECRET}',
            kid: 'enc-key-1',
            claims: {
              internalId: 'internal-device-9',
              tier: '$.request.body.tier',
              entitlements: ['premium', 'beta'],
            },
          },
          jwt: {
            issuer: 'token-weaver',
            ttl: 3600,
          },
        },
        {
          name: 'encrypted-delegated',
          type: 'delegated',
          upstream: {
            url: `http://127.0.0.1:${upstreamPort}/verify`,
            method: 'POST',
            timeout_ms: 1_000,
            auth: {
              type: 'bearer',
              token: '${UPSTREAM_API_TOKEN}',
            },
            body_mapping: {
              username: '$.request.body.username',
              password: '$.request.body.password',
            },
          },
          response_mapping: {
            success_condition: "$.status == 'ok'",
            claims: {
              sub: '$.response.body.userId',
            },
          },
          encrypted_claims: {
            secret: '${TW_ENC_SECRET}',
            claim: 'private',
            claims: {
              upstreamUserId: '$.response.body.userId',
              upstreamStatus: '$.response.body.status',
            },
          },
          jwt: {
            issuer: 'token-weaver',
            ttl: 3600,
          },
        },
        {
          name: 'hmac-client',
          type: 'direct',
          credentials: [
            {
              secret: '${HMAC_CLIENT_SECRET}',
              claims: {
                sub: 'hmac-client',
                scope: 'mobile',
              },
            },
          ],
          jwt: {
            algorithm: 'HS256',
            secret: '${TW_HMAC_SECRET}',
            issuer: 'token-weaver',
            ttl: 1800,
          },
        },
      ],
    },
    null,
    2,
  );
}

void describe('Token Weaver e2e', () => {
  void before(async () => {
    testContext.tmpDir = mkdtempSync(join(tmpdir(), 'token-weaver-e2e-'));

    const { privateKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    const privateKeyPath = join(testContext.tmpDir, 'private-key.pem');
    writeFileSync(privateKeyPath, privateKey, 'utf8');

    testContext.upstreamServer = createServer(createUpstreamHandler('upstream-service-token'));
    await startServer(testContext.upstreamServer);
    const upstreamPort = getListeningPort(testContext.upstreamServer);

    const configPath = join(testContext.tmpDir, 'token-weaver.config.json');
    writeFileSync(configPath, createTestConfig(upstreamPort), 'utf8');

    testContext.servicePort = await getAvailablePort();
    testContext.output = [];
    testContext.serviceProcess = spawn(process.execPath, ['--import=tsx', 'src/index.ts'], {
      cwd: process.cwd(),
      env: {
        ...process.env,
        NODE_ENV: 'test',
        PORT: String(testContext.servicePort),
        TOKEN_WEAVER_CONFIG_PATH: configPath,
        TOKEN_WEAVER_PRIVATE_KEY_PATH: privateKeyPath,
        TOKEN_WEAVER_KID: 'token-weaver-e2e',
        TW_INBOUND_KEY: 'inbound-key',
        STATIC_CLIENT_SECRET: 'static-secret',
        UPSTREAM_API_TOKEN: 'upstream-service-token',
        HMAC_CLIENT_SECRET: 'hmac-client-secret',
        TW_HMAC_SECRET: 'test-hmac-shared-secret',
        TW_ENC_SECRET: encryptionSecret,
      },
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    testContext.serviceProcess.stdout.on('data', (chunk) => {
      testContext.output.push(String(chunk));
    });
    testContext.serviceProcess.stderr.on('data', (chunk) => {
      testContext.output.push(String(chunk));
    });

    await waitForServiceReady(testContext.servicePort, testContext.output);
  });

  void after(async () => {
    testContext.serviceProcess.kill('SIGTERM');
    await new Promise((resolve) => testContext.serviceProcess.once('exit', resolve));
    await new Promise<void>((resolve, reject) => {
      testContext.upstreamServer.close((error) => {
        if (error) {
          reject(error);
          return;
        }

        resolve();
      });
    });
    rmSync(testContext.tmpDir, { recursive: true, force: true });
  });

  void it('serves health and jwks endpoints', async () => {
    const healthResponse = await globalThis.fetch(
      `http://127.0.0.1:${testContext.servicePort}/health`,
    );
    assert.equal(healthResponse.status, 200);
    const healthBody = (await healthResponse.json()) as {
      status: string;
      timestamp: string;
      service: string;
    };
    assert.deepEqual(healthBody, {
      status: 'ok',
      timestamp: healthBody.timestamp,
      service: 'token-weaver',
    });

    const jwksResponse = await globalThis.fetch(
      `http://127.0.0.1:${testContext.servicePort}/.well-known/jwks.json`,
    );
    assert.equal(jwksResponse.status, 200);
    const jwks = (await jwksResponse.json()) as { keys: Array<Record<string, unknown>> };
    assert.equal(jwks.keys.length, 1);
    assert.equal(jwks.keys[0]?.kid, 'token-weaver-e2e');
    assert.equal(jwks.keys[0]?.alg, 'RS256');
  });

  void it('issues a JWT for the direct strategy', async () => {
    const response = await globalThis.fetch(
      `http://127.0.0.1:${testContext.servicePort}/auth/static-client`,
      {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': 'inbound-key',
      },
      body: JSON.stringify({
        secret: 'static-secret',
        deviceId: 'client-device-001',
        customClaim: 'example-value',
      }),
      },
    );

    assert.equal(response.status, 200);
    const body = (await response.json()) as { token: string; expires_in: number };
    assert.equal(body.expires_in, 3600);

    const [encodedHeader, encodedPayload] = body.token.split('.');
    const header = decodeJwtPart(encodedHeader!);
    const payload = decodeJwtPart(encodedPayload!);

    assert.equal(header.kid, 'token-weaver-e2e');
    assert.equal(payload.iss, 'token-weaver');
    assert.equal(payload.sub, 'client-device-001');
    assert.deepEqual(payload.scope, ['general']);
  });

  void it('rejects invalid direct credentials', async () => {
    const response = await globalThis.fetch(
      `http://127.0.0.1:${testContext.servicePort}/auth/static-client`,
      {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': 'inbound-key',
      },
      body: JSON.stringify({ secret: 'wrong-secret' }),
      },
    );

    assert.equal(response.status, 401);
  });

  void it('issues a JWT for the delegated strategy', async () => {
    const response = await globalThis.fetch(
      `http://127.0.0.1:${testContext.servicePort}/auth/delegated-player-auth`,
      {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': 'inbound-key',
      },
      body: JSON.stringify({
        username: 'player@example.com',
        password: 'correct-password',
      }),
      },
    );

    assert.equal(response.status, 200);
    const body = (await response.json()) as { token: string };
    const [, encodedPayload] = body.token.split('.');
    const payload = decodeJwtPart(encodedPayload!);

    assert.equal(payload.sub, 'player-123');
    assert.deepEqual(payload.scope, ['general']);
  });

  void it('returns 401 when delegated authentication is rejected', async () => {
    const response = await globalThis.fetch(
      `http://127.0.0.1:${testContext.servicePort}/auth/delegated-player-auth`,
      {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': 'inbound-key',
      },
      body: JSON.stringify({
        username: 'player@example.com',
        password: 'wrong-password',
      }),
      },
    );

    assert.equal(response.status, 401);
  });

  void it('returns 503 when delegated authentication times out', async () => {
    const response = await globalThis.fetch(
      `http://127.0.0.1:${testContext.servicePort}/auth/delegated-timeout`,
      {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': 'inbound-key',
      },
      body: JSON.stringify({
        username: 'player@example.com',
        password: 'correct-password',
      }),
      },
    );

    assert.equal(response.status, 503);
  });

  void it('issues an HS256 JWT for the hmac-client strategy', async () => {
    const response = await globalThis.fetch(
      `http://127.0.0.1:${testContext.servicePort}/auth/hmac-client`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ secret: 'hmac-client-secret' }),
      },
    );

    assert.equal(response.status, 200);
    const body = (await response.json()) as { token: string; expires_in: number };
    assert.equal(body.expires_in, 1800);

    const [encodedHeader, encodedPayload, encodedSignature] = body.token.split('.');
    const header = decodeJwtPart(encodedHeader!);
    const payload = decodeJwtPart(encodedPayload!);

    assert.equal(header.alg, 'HS256');
    assert.equal(header.kid, undefined, 'HS256 tokens must not include kid');
    assert.equal(payload.iss, 'token-weaver');
    assert.equal(payload.sub, 'hmac-client');
    assert.equal(payload.scope, 'mobile');
    assert.equal(typeof payload.exp, 'number');

    // Verify signature with crypto.createHmac (same as CloudFront Function would)
    const signingInput = `${encodedHeader}.${encodedPayload}`;
    const expectedSignature = createHmac('sha256', 'test-hmac-shared-secret')
      .update(signingInput)
      .digest('base64url');
    assert.equal(encodedSignature, expectedSignature);
  });

  void it('JWKS still returns RS256 key in mixed-mode deployment', async () => {
    const jwksResponse = await globalThis.fetch(
      `http://127.0.0.1:${testContext.servicePort}/.well-known/jwks.json`,
    );
    assert.equal(jwksResponse.status, 200);
    const jwks = (await jwksResponse.json()) as { keys: Array<Record<string, unknown>> };
    assert.equal(jwks.keys.length, 1);
    assert.equal(jwks.keys[0]?.alg, 'RS256');
  });

  void it('maps 403 upstream response to 403 with body message', async () => {
    const response = await globalThis.fetch(
      `http://127.0.0.1:${testContext.servicePort}/auth/delegated-error-mapped`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': 'inbound-key' },
        body: JSON.stringify({ username: 'banned@example.com', password: 'anything' }),
      },
    );

    assert.equal(response.status, 403);
    const body = (await response.json()) as { message: string };
    assert.equal(body.message, 'Account suspended');
  });

  void it('maps 401 upstream response to 401 with literal message', async () => {
    const response = await globalThis.fetch(
      `http://127.0.0.1:${testContext.servicePort}/auth/delegated-error-mapped`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': 'inbound-key' },
        body: JSON.stringify({ username: 'player@example.com', password: 'wrong' }),
      },
    );

    assert.equal(response.status, 401);
    const body = (await response.json()) as { message: string };
    assert.equal(body.message, 'Invalid credentials');
  });

  void it('succeeds with error_mappings configured when upstream returns success', async () => {
    const response = await globalThis.fetch(
      `http://127.0.0.1:${testContext.servicePort}/auth/delegated-error-mapped`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': 'inbound-key' },
        body: JSON.stringify({ username: 'valid@example.com', password: 'correct' }),
      },
    );

    assert.equal(response.status, 200);
    const body = (await response.json()) as { token: string };
    const [, encodedPayload] = body.token.split('.');
    const payload = decodeJwtPart(encodedPayload!);
    assert.equal(payload.sub, 'mapped-user-1');
  });

  void it('catch-all error mapping handles any upstream rejection', async () => {
    const response = await globalThis.fetch(
      `http://127.0.0.1:${testContext.servicePort}/auth/delegated-catchall`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': 'inbound-key' },
        body: JSON.stringify({ username: 'banned@example.com', password: 'anything' }),
      },
    );

    assert.equal(response.status, 401);
    const body = (await response.json()) as { message: string };
    assert.equal(body.message, 'Authentication failed');
  });

  void it('encrypts the encrypted_claims block into an opaque JWT claim', async () => {
    const response = await globalThis.fetch(
      `http://127.0.0.1:${testContext.servicePort}/auth/encrypted-direct`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          secret: 'static-secret',
          deviceId: 'client-device-002',
          tier: 'gold',
        }),
      },
    );

    assert.equal(response.status, 200);
    const body = (await response.json()) as { token: string };
    const [, encodedPayload] = body.token.split('.');
    const payload = decodeJwtPart(encodedPayload!);

    // Public claims stay readable.
    assert.equal(payload.sub, 'client-device-002');
    assert.deepEqual(payload.scope, ['general']);

    // The encrypted block is a single opaque compact JWE, and none of its values leak into the
    // readable payload.
    assert.equal(typeof payload.enc, 'string');
    assert.equal((payload.enc as string).split('.').length, 5, 'expected a compact JWE');
    const rawPayload = Buffer.from(encodedPayload!, 'base64url').toString('utf8');
    assert.ok(!rawPayload.includes('internal-device-9'), 'encrypted value leaked in cleartext');
    assert.ok(!rawPayload.includes('gold'), 'encrypted value leaked in cleartext');

    const decrypted = await decryptClaims(payload.enc as string, [encryptionKey]);
    assert.deepEqual(decrypted, {
      internalId: 'internal-device-9',
      tier: 'gold',
      entitlements: ['premium', 'beta'],
    });
  });

  void it('encrypts claims mapped from an upstream response', async () => {
    const response = await globalThis.fetch(
      `http://127.0.0.1:${testContext.servicePort}/auth/encrypted-delegated`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: 'player@example.com',
          password: 'correct-password',
        }),
      },
    );

    assert.equal(response.status, 200);
    const body = (await response.json()) as { token: string };
    const payload = decodeJwtPart(body.token.split('.')[1]!);

    assert.equal(payload.sub, 'player-123');
    assert.equal(payload.enc, undefined, 'blob must use the configured claim name');
    assert.equal(typeof payload.private, 'string');

    const decrypted = await decryptClaims(payload.private as string, [encryptionKey]);
    assert.deepEqual(decrypted, { upstreamUserId: 'player-123', upstreamStatus: 'ok' });
  });

  void it('decrypts the blob during verification with the shared secret', async () => {
    const response = await globalThis.fetch(
      `http://127.0.0.1:${testContext.servicePort}/auth/encrypted-direct`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          secret: 'static-secret',
          deviceId: 'client-device-003',
          tier: 'silver',
        }),
      },
    );
    const { token } = (await response.json()) as { token: string };

    const authenticate = compileAuth({
      mode: 'jwt-jwks',
      issuer: 'token-weaver',
      jwksUri: `http://127.0.0.1:${testContext.servicePort}/.well-known/jwks.json`,
      encryptedClaims: { secret: encryptionSecret },
    });

    const payload = await authenticate({ authorizationHeader: `Bearer ${token}` });
    assert.equal(payload.sub, 'client-device-003');
    assert.deepEqual(payload.enc, {
      internalId: 'internal-device-9',
      tier: 'silver',
      entitlements: ['premium', 'beta'],
    });
  });

  void it('rejects verification when the encryption secret does not match', async () => {
    const response = await globalThis.fetch(
      `http://127.0.0.1:${testContext.servicePort}/auth/encrypted-direct`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ secret: 'static-secret', deviceId: 'device-x', tier: 'bronze' }),
      },
    );
    const { token } = (await response.json()) as { token: string };

    const authenticate = compileAuth({
      mode: 'jwt-jwks',
      issuer: 'token-weaver',
      jwksUri: `http://127.0.0.1:${testContext.servicePort}/.well-known/jwks.json`,
      encryptedClaims: {
        secret: Buffer.from('wrong-key-wrong-key-wrong-key-32').toString('base64'),
      },
    });

    await assert.rejects(
      authenticate({ authorizationHeader: `Bearer ${token}` }),
      (error: Error & { status?: number }) => {
        assert.equal(error.status, 401);
        return true;
      },
    );
  });

  void it('rejects a token missing the required encrypted claim', async () => {
    // static-client issues no encrypted block, so a verifier that requires one must reject it.
    const response = await globalThis.fetch(
      `http://127.0.0.1:${testContext.servicePort}/auth/static-client`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': 'inbound-key' },
        body: JSON.stringify({ secret: 'static-secret', deviceId: 'device-y' }),
      },
    );
    const { token } = (await response.json()) as { token: string };

    const options = {
      mode: 'jwt-jwks' as const,
      issuer: 'token-weaver',
      jwksUri: `http://127.0.0.1:${testContext.servicePort}/.well-known/jwks.json`,
    };

    await assert.rejects(
      compileAuth({ ...options, encryptedClaims: { secret: encryptionSecret } })({
        authorizationHeader: `Bearer ${token}`,
      }),
      (error: Error & { status?: number }) => {
        assert.equal(error.status, 401);
        return true;
      },
    );

    // ...but passes when the blob is declared optional.
    const payload = await compileAuth({
      ...options,
      encryptedClaims: { secret: encryptionSecret, required: false },
    })({ authorizationHeader: `Bearer ${token}` });
    assert.equal(payload.sub, 'device-y');
  });

  void it('catch-all error mapping does not affect successful upstream auth', async () => {
    const response = await globalThis.fetch(
      `http://127.0.0.1:${testContext.servicePort}/auth/delegated-catchall`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': 'inbound-key' },
        body: JSON.stringify({ username: 'valid@example.com', password: 'correct' }),
      },
    );

    assert.equal(response.status, 200);
    const body = (await response.json()) as { token: string };
    const [, encodedPayload] = body.token.split('.');
    const payload = decodeJwtPart(encodedPayload!);
    assert.equal(payload.sub, 'mapped-user-1');
  });

  void it('publishes the OpenAPI spec at its own URL', async () => {
    const response = await globalThis.fetch(
      `http://127.0.0.1:${testContext.servicePort}/api-docs.yaml`,
    );

    assert.equal(response.status, 200);
    assert.match(response.headers.get('content-type') ?? '', /yaml/);

    // Must be the real document, fetchable by anything - another docs site, codegen, a
    // contract test - without scraping swagger-ui internals.
    const spec = YAML.parse(await response.text()) as {
      openapi?: string;
      info?: { title?: string };
      paths?: Record<string, unknown>;
    };
    assert.match(spec.openapi ?? '', /^3\./);
    assert.equal(spec.info?.title, 'Token Weaver API');
    assert.ok(Object.keys(spec.paths ?? {}).length > 0, 'spec should declare paths');
  });

  void it('serves the Swagger UI pointed at that URL rather than an embedded doc', async () => {
    const page = await globalThis.fetch(`http://127.0.0.1:${testContext.servicePort}/api-docs/`);
    assert.equal(page.status, 200);

    const initScript = await globalThis.fetch(
      `http://127.0.0.1:${testContext.servicePort}/api-docs/swagger-ui-init.js`,
    );
    assert.equal(initScript.status, 200);
    const initBody = await initScript.text();
    // The UI fetches the spec by URL now, so the document is no longer inlined here.
    assert.match(initBody, /api-docs\.yaml/);
    assert.ok(!initBody.includes('"openapi": "3.'), 'spec should not be embedded in swagger-ui-init.js');
  });

});

void describe('Token Weaver e2e — HS256-only deployment', () => {
  const hs256Context = {} as TestContext;

  void before(async () => {
    hs256Context.tmpDir = mkdtempSync(join(tmpdir(), 'token-weaver-hs256-'));

    const configPath = join(hs256Context.tmpDir, 'token-weaver.config.json');
    writeFileSync(
      configPath,
      JSON.stringify({
        strategies: [
          {
            name: 'hmac-only',
            type: 'direct',
            credentials: [
              {
                secret: '${HMAC_CLIENT_SECRET}',
                claims: { sub: 'hmac-sub', scope: 'read' },
              },
            ],
            jwt: {
              algorithm: 'HS256',
              secret: '${TW_HMAC_SECRET}',
              issuer: 'token-weaver',
              ttl: 900,
            },
          },
        ],
      }),
    );

    hs256Context.servicePort = await getAvailablePort();
    hs256Context.output = [];
    hs256Context.serviceProcess = spawn(process.execPath, ['--import=tsx', 'src/index.ts'], {
      cwd: process.cwd(),
      env: {
        ...process.env,
        NODE_ENV: 'test',
        PORT: String(hs256Context.servicePort),
        TOKEN_WEAVER_CONFIG_PATH: configPath,
        HMAC_CLIENT_SECRET: 'hmac-secret',
        TW_HMAC_SECRET: 'hs256-only-shared-secret',
      },
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    hs256Context.serviceProcess.stdout.on('data', (chunk) => {
      hs256Context.output.push(String(chunk));
    });
    hs256Context.serviceProcess.stderr.on('data', (chunk) => {
      hs256Context.output.push(String(chunk));
    });

    await waitForServiceReady(hs256Context.servicePort, hs256Context.output);
  });

  void after(async () => {
    hs256Context.serviceProcess.kill('SIGTERM');
    await new Promise((resolve) => hs256Context.serviceProcess.once('exit', resolve));
    rmSync(hs256Context.tmpDir, { recursive: true, force: true });
  });

  void it('starts without RSA key and issues HS256 tokens', async () => {
    const response = await globalThis.fetch(
      `http://127.0.0.1:${hs256Context.servicePort}/auth/hmac-only`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ secret: 'hmac-secret' }),
      },
    );

    assert.equal(response.status, 200);
    const body = (await response.json()) as { token: string; expires_in: number };
    assert.equal(body.expires_in, 900);

    const [encodedHeader, encodedPayload, encodedSignature] = body.token.split('.');
    const header = decodeJwtPart(encodedHeader!);
    assert.equal(header.alg, 'HS256');
    assert.equal(header.kid, undefined);

    const signingInput = `${encodedHeader}.${encodedPayload}`;
    const expectedSignature = createHmac('sha256', 'hs256-only-shared-secret')
      .update(signingInput)
      .digest('base64url');
    assert.equal(encodedSignature, expectedSignature);
  });

  void it('returns empty JWKS keys in HS256-only mode', async () => {
    const jwksResponse = await globalThis.fetch(
      `http://127.0.0.1:${hs256Context.servicePort}/.well-known/jwks.json`,
    );
    assert.equal(jwksResponse.status, 200);
    const jwks = (await jwksResponse.json()) as { keys: Array<Record<string, unknown>> };
    assert.equal(jwks.keys.length, 0);
  });
});

/**
 * Token exchange: an upstream identity provider's JWT is traded for one of ours.
 *
 * The value is that consumers trust ONE issuer and one claim vocabulary while upstream IdPs
 * change behind it - so these tests check both that the upstream token is genuinely verified
 * (signature, issuer, required claims) and that OUR token carries OUR claims, not a passthrough
 * of theirs.
 */
void describe('Token Weaver e2e — JWT exchange strategy', () => {
  const exchangeContext = {} as TestContext & { idpServer: Server; signUpstream: (claims: Record<string, unknown>, opts?: { issuer?: string }) => Promise<string>; rogueSign: (claims: Record<string, unknown>) => Promise<string> };

  const IDP_ISSUER = 'https://idp.test/';

  void before(async () => {
    exchangeContext.tmpDir = mkdtempSync(join(tmpdir(), 'token-weaver-exchange-'));

    // The upstream IdP: an RSA key pair, published as a JWKS the service will fetch.
    const idp = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    const idpPrivate = await importPKCS8(idp.privateKey, 'RS256');
    const idpPublicJwk = await exportJWK(await importSPKI(idp.publicKey, 'RS256'));
    idpPublicJwk.kid = 'idp-key-1';
    idpPublicJwk.alg = 'RS256';
    idpPublicJwk.use = 'sig';

    // A DIFFERENT key, never published - used to prove signature verification actually happens.
    const rogue = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    const roguePrivate = await importPKCS8(rogue.privateKey, 'RS256');

    exchangeContext.signUpstream = (claims, opts = {}) =>
      new SignJWT(claims)
        .setProtectedHeader({ alg: 'RS256', kid: 'idp-key-1' })
        .setIssuer(opts.issuer ?? IDP_ISSUER)
        .setAudience('ipb')
        .setIssuedAt()
        .setExpirationTime('5m')
        .sign(idpPrivate);

    exchangeContext.rogueSign = (claims) =>
      new SignJWT(claims)
        .setProtectedHeader({ alg: 'RS256', kid: 'idp-key-1' })
        .setIssuer(IDP_ISSUER)
        .setAudience('ipb')
        .setIssuedAt()
        .setExpirationTime('5m')
        .sign(roguePrivate);

    exchangeContext.idpServer = createServer((req, res) => {
      if (req.url === '/.well-known/jwks.json') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ keys: [idpPublicJwk] }));
        return;
      }
      res.writeHead(404);
      res.end();
    });
    await startServer(exchangeContext.idpServer);
    const idpPort = getListeningPort(exchangeContext.idpServer);

    const servicePrivateKey = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    }).privateKey;
    const privateKeyPath = join(exchangeContext.tmpDir, 'token-weaver.key.pem');
    writeFileSync(privateKeyPath, servicePrivateKey, 'utf8');

    const configPath = join(exchangeContext.tmpDir, 'token-weaver.config.json');
    writeFileSync(
      configPath,
      JSON.stringify({
        strategies: [
          {
            name: 'ipb',
            type: 'jwt',
            verify: {
              jwks_uri: `http://127.0.0.1:${idpPort}/.well-known/jwks.json`,
              issuer: IDP_ISSUER,
              audience: 'ipb',
              requirements: [{ type: 'scope', value: 'ipb:play' }],
            },
            claims: {
              // OUR vocabulary, built from THEIR identity.
              sub: '$.request.jwt.sub',
              upstreamEmail: '$.request.jwt.email',
              routes: { whitelist: ['ipb/v1/getPlayerState'] },
            },
            jwt: { algorithm: 'RS256', issuer: 'token-weaver', ttl: 600 },
          },
        ],
      }),
    );

    exchangeContext.servicePort = await getAvailablePort();
    exchangeContext.output = [];
    exchangeContext.serviceProcess = spawn(process.execPath, ['--import=tsx', 'src/index.ts'], {
      cwd: process.cwd(),
      env: {
        ...process.env,
        NODE_ENV: 'test',
        PORT: String(exchangeContext.servicePort),
        TOKEN_WEAVER_CONFIG_PATH: configPath,
        TOKEN_WEAVER_PRIVATE_KEY_PATH: privateKeyPath,
        TOKEN_WEAVER_KID: 'token-weaver-exchange',
      },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    exchangeContext.serviceProcess.stdout.on('data', (chunk) => {
      exchangeContext.output.push(String(chunk));
    });
    exchangeContext.serviceProcess.stderr.on('data', (chunk) => {
      exchangeContext.output.push(String(chunk));
    });

    await waitForServiceReady(exchangeContext.servicePort, exchangeContext.output);
  });

  void after(async () => {
    exchangeContext.serviceProcess.kill('SIGTERM');
    await new Promise((resolve) => exchangeContext.serviceProcess.once('exit', resolve));
    await new Promise((resolve) => exchangeContext.idpServer.close(resolve));
    rmSync(exchangeContext.tmpDir, { recursive: true, force: true });
  });

  const exchange = async (authorization?: string) =>
    globalThis.fetch(`http://127.0.0.1:${exchangeContext.servicePort}/auth/ipb`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(authorization ? { Authorization: authorization } : {}),
      },
      body: JSON.stringify({}),
    });

  void it('exchanges a verified upstream token for one carrying OUR claims', async () => {
    const upstream = await exchangeContext.signUpstream({
      sub: 'upstream-user-42',
      email: 'player@idp.test',
      scope: ['ipb:play'],
    });

    const response = await exchange(`Bearer ${upstream}`);
    assert.equal(response.status, 200);

    const body = (await response.json()) as { token: string; expires_in: number };
    assert.equal(body.expires_in, 600);

    const [, encodedPayload] = body.token.split('.');
    const payload = decodeJwtPart(encodedPayload!);
    // Ours, not a passthrough: our issuer, our ttl, and claims we chose.
    assert.equal(payload.iss, 'token-weaver');
    assert.equal(payload.sub, 'upstream-user-42');
    assert.equal(payload.upstreamEmail, 'player@idp.test');
    assert.deepEqual(payload.routes, { whitelist: ['ipb/v1/getPlayerState'] });
    // The upstream's own scope is NOT carried over unless mapped.
    assert.equal(payload.scope, undefined);
  });

  void it('rejects a token signed by a key the JWKS does not publish', async () => {
    const forged = await exchangeContext.rogueSign({ sub: 'attacker', scope: ['ipb:play'] });
    const response = await exchange(`Bearer ${forged}`);
    assert.equal(response.status, 401);
  });

  void it('rejects a token from a different issuer', async () => {
    const wrongIssuer = await exchangeContext.signUpstream(
      { sub: 'upstream-user-42', scope: ['ipb:play'] },
      { issuer: 'https://someone-else.test/' },
    );
    const response = await exchange(`Bearer ${wrongIssuer}`);
    assert.equal(response.status, 401);
  });

  void it('rejects a verified token that lacks the required scope with 403, not 401', async () => {
    // Distinguishing these matters: the caller learns their token is fine but not entitled.
    const noScope = await exchangeContext.signUpstream({ sub: 'upstream-user-42', scope: ['other'] });
    const response = await exchange(`Bearer ${noScope}`);
    assert.equal(response.status, 403);
  });

  void it('rejects a request with no token', async () => {
    const response = await exchange();
    assert.equal(response.status, 401);
  });
});
