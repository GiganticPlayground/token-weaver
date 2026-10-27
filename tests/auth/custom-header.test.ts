import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import type { Request, RequestHandler, Response } from 'express';
import { SignJWT } from 'jose';

import {
  AuthError,
  compileAuth,
  createAuthMiddleware,
  createAuthMiddlewareFromEnv,
} from '../../src/auth/index';

const ISSUER = 'https://issuer.test';
const SECRET = 'custom-header-secret-with-enough-entropy';
const SERVICE_KEY = 'internal-service-key-abc123';

type RunResult = { error: unknown; req: Request };

/** Invoke a middleware with the given headers (lower-case names, as Node delivers them). */
function runMiddleware(
  middleware: RequestHandler,
  headers: Record<string, string> = {},
): Promise<RunResult> {
  const req = { headers, baseUrl: '', path: '/' } as unknown as Request;
  return new Promise((resolve) => {
    middleware(req, {} as Response, (error?: unknown) => resolve({ error, req }));
  });
}

function signHs256(): Promise<string> {
  return new SignJWT({})
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuer(ISSUER)
    .setSubject('user-1')
    .setExpirationTime('1h')
    .sign(Buffer.from(SECRET));
}

function assertUnauthorized(result: RunResult, message?: string): void {
  assert.ok(result.error instanceof AuthError, 'expected an AuthError');
  assert.equal(result.error.status, 401);
  if (message !== undefined) assert.equal(result.error.message, message);
}

void describe('custom credential header', () => {
  const serviceKey = (): RequestHandler =>
    createAuthMiddleware({
      mode: 'static',
      staticToken: SERVICE_KEY,
      header: 'X-Service-Key',
      scheme: 'none',
    });

  void it('accepts a static key sent as the whole value of a custom header', async () => {
    const result = await runMiddleware(serviceKey(), { 'x-service-key': SERVICE_KEY });
    assert.equal(result.error, undefined);
    assert.deepEqual(result.req.jwtPayload, {});
  });

  void it('rejects a wrong key, a missing header, and the key sent in Authorization', async () => {
    assertUnauthorized(
      await runMiddleware(serviceKey(), { 'x-service-key': 'wrong' }),
      'Invalid token',
    );
    assertUnauthorized(await runMiddleware(serviceKey()), 'Missing x-service-key header');
    assertUnauthorized(
      await runMiddleware(serviceKey(), { authorization: `Bearer ${SERVICE_KEY}` }),
      'Missing x-service-key header',
    );
  });

  void it('rejects an empty value with scheme none', async () => {
    assertUnauthorized(
      await runMiddleware(serviceKey(), { 'x-service-key': '   ' }),
      'Malformed x-service-key header',
    );
  });

  void it('reads Bearer <token> from a custom header with the default scheme', async () => {
    const mw = createAuthMiddleware({
      mode: 'jwt-hs256',
      issuer: ISSUER,
      secret: SECRET,
      header: 'x-forwarded-authorization',
    });
    const ok = await runMiddleware(mw, {
      'x-forwarded-authorization': `Bearer ${await signHs256()}`,
    });
    assert.equal(ok.error, undefined);
    assert.equal(ok.req.jwtPayload?.sub, 'user-1');
    assertUnauthorized(
      await runMiddleware(mw, { 'x-forwarded-authorization': await signHs256() }),
      'Malformed x-forwarded-authorization header',
    );
  });

  void it('lets each strategy read its own header', async () => {
    const mw = createAuthMiddleware({
      strategies: [
        { mode: 'static', staticToken: SERVICE_KEY, header: 'x-service-key', scheme: 'none' },
        { mode: 'jwt-hs256', issuer: ISSUER, secret: SECRET },
      ],
    });
    assert.equal((await runMiddleware(mw, { 'x-service-key': SERVICE_KEY })).error, undefined);
    const jwt = await runMiddleware(mw, { authorization: `Bearer ${await signHs256()}` });
    assert.equal(jwt.error, undefined);
    assert.equal(jwt.req.jwtPayload?.sub, 'user-1');
    assertUnauthorized(await runMiddleware(mw, { 'x-service-key': 'wrong' }));
  });

  void it('keeps the default Authorization behavior and messages', async () => {
    const mw = createAuthMiddleware({ mode: 'static', staticToken: SERVICE_KEY });
    assert.equal(
      (await runMiddleware(mw, { authorization: `Bearer ${SERVICE_KEY}` })).error,
      undefined,
    );
    assertUnauthorized(
      await runMiddleware(mw, { 'x-service-key': SERVICE_KEY }),
      'Missing Authorization header',
    );
    assertUnauthorized(
      await runMiddleware(mw, { authorization: SERVICE_KEY }),
      'Malformed Authorization header',
    );
  });

  void it('works through the core API with a headers map', async () => {
    const authenticate = compileAuth({
      mode: 'static',
      staticToken: SERVICE_KEY,
      header: 'x-service-key',
      scheme: 'none',
    });
    assert.deepEqual(await authenticate({ headers: { 'x-service-key': SERVICE_KEY } }), {});
    await assert.rejects(authenticate({ headers: {} }), AuthError);
  });

  void it('fails fast on an empty header name or an unknown scheme', () => {
    assert.throws(
      () => createAuthMiddleware({ mode: 'static', staticToken: SERVICE_KEY, header: ' ' }),
      /'header' must not be empty/,
    );
    assert.throws(
      () =>
        createAuthMiddleware({
          mode: 'static',
          staticToken: SERVICE_KEY,
          scheme: 'basic' as never,
        }),
      /'scheme' must be 'bearer' or 'none'/,
    );
  });

  void it('is configurable from env with HEADER and SCHEME', async () => {
    const mw = createAuthMiddlewareFromEnv({
      env: {
        AUTH_MODE: 'static',
        AUTH_STATIC_TOKEN: SERVICE_KEY,
        AUTH_HEADER: 'X-Service-Key',
        AUTH_SCHEME: 'none',
      },
    });
    assert.equal((await runMiddleware(mw, { 'x-service-key': SERVICE_KEY })).error, undefined);
    assert.throws(
      () =>
        createAuthMiddlewareFromEnv({
          env: { AUTH_MODE: 'static', AUTH_STATIC_TOKEN: SERVICE_KEY, AUTH_SCHEME: 'basic' },
        }),
      /AUTH_SCHEME must be 'bearer' or 'none'/,
    );
  });
});
