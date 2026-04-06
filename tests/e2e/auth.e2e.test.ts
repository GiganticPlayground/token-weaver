import { generateKeyPairSync } from 'crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'fs';
import assert from 'node:assert/strict';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { after, before, describe, it } from 'node:test';
import { tmpdir } from 'os';
import { join } from 'path';

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
                sub: 'client-device-001',
                scope: ['general'],
                customClaim: 'example-value',
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
      body: JSON.stringify({ secret: 'static-secret' }),
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
});
