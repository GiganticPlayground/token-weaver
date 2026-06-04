import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import type { Request, RequestHandler, Response } from 'express';
import { SignJWT } from 'jose';

import { ForbiddenError, createAuthMiddlewareFromEnv } from '../../src/auth/index';

const ISSUER = 'https://issuer.test';
const SECRET = 'env-secret-value-with-enough-entropy';

type RunResult = { error: unknown; req: Request };

function runMiddleware(
  middleware: RequestHandler,
  reqInit: { authorization?: string; path?: string } = {},
): Promise<RunResult> {
  const headers =
    reqInit.authorization === undefined ? {} : { authorization: reqInit.authorization };
  const req = { headers, baseUrl: '', path: reqInit.path ?? '/' } as unknown as Request;

  return new Promise((resolve) => {
    middleware(req, {} as Response, (error?: unknown) => resolve({ error, req }));
  });
}

function signHs256(claims: Record<string, unknown>): Promise<string> {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuer(ISSUER)
    .setSubject('user-1')
    .setExpirationTime('1h')
    .sign(Buffer.from(SECRET));
}

void describe('createAuthMiddlewareFromEnv', () => {
  void it('builds a jwt-hs256 middleware from env vars', async () => {
    const mw = createAuthMiddlewareFromEnv({
      env: { AUTH_MODE: 'jwt-hs256', AUTH_ISSUER: ISSUER, AUTH_SECRET: SECRET },
    });
    const result = await runMiddleware(mw, { authorization: `Bearer ${await signHs256({})}` });
    assert.equal(result.error, undefined);
    assert.equal(result.req.jwtPayload?.sub, 'user-1');
  });

  void it('builds a static-mode middleware from env vars', async () => {
    const mw = createAuthMiddlewareFromEnv({
      env: { AUTH_MODE: 'static', AUTH_STATIC_TOKEN: 'tok-123' },
    });
    assert.equal((await runMiddleware(mw, { authorization: 'Bearer tok-123' })).error, undefined);
    assert.ok((await runMiddleware(mw, { authorization: 'Bearer nope' })).error);
  });

  void it('honors a custom prefix', async () => {
    const mw = createAuthMiddlewareFromEnv({
      prefix: 'MYAPP_',
      env: { MYAPP_MODE: 'jwt-hs256', MYAPP_ISSUER: ISSUER, MYAPP_SECRET: SECRET },
    });
    assert.equal(
      (await runMiddleware(mw, { authorization: `Bearer ${await signHs256({})}` })).error,
      undefined,
    );
  });

  void it('wires paths config and enforces it', async () => {
    const mw = createAuthMiddlewareFromEnv({
      env: {
        AUTH_MODE: 'jwt-hs256',
        AUTH_ISSUER: ISSUER,
        AUTH_SECRET: SECRET,
        AUTH_WHITELIST_CLAIM: 'whitelist',
      },
    });
    const token = await signHs256({ whitelist: ['/nexus/*'] });
    const ok = await runMiddleware(mw, { authorization: `Bearer ${token}`, path: '/nexus/data' });
    assert.equal(ok.error, undefined);
    const denied = await runMiddleware(mw, { authorization: `Bearer ${token}`, path: '/admin' });
    assert.ok(denied.error instanceof ForbiddenError);
  });

  void it('parses AUTH_REQUIREMENTS JSON and enforces it', async () => {
    const mw = createAuthMiddlewareFromEnv({
      env: {
        AUTH_MODE: 'jwt-hs256',
        AUTH_ISSUER: ISSUER,
        AUTH_SECRET: SECRET,
        AUTH_REQUIREMENTS: JSON.stringify([{ type: 'scope', value: 'nexus:read' }]),
      },
    });
    assert.equal(
      (
        await runMiddleware(mw, {
          authorization: `Bearer ${await signHs256({ scope: 'nexus:read' })}`,
        })
      ).error,
      undefined,
    );
    assert.ok(
      (await runMiddleware(mw, { authorization: `Bearer ${await signHs256({ scope: 'x' })}` }))
        .error instanceof ForbiddenError,
    );
  });

  void it('throws on a missing/invalid AUTH_MODE', () => {
    assert.throws(() => createAuthMiddlewareFromEnv({ env: {} }), /MODE must be/);
    assert.throws(
      () => createAuthMiddlewareFromEnv({ env: { AUTH_MODE: 'nope' } }),
      /MODE must be/,
    );
  });

  void it('throws on invalid AUTH_REQUIREMENTS JSON', () => {
    assert.throws(
      () =>
        createAuthMiddlewareFromEnv({
          env: {
            AUTH_MODE: 'jwt-hs256',
            AUTH_ISSUER: ISSUER,
            AUTH_SECRET: SECRET,
            AUTH_REQUIREMENTS: '{not json',
          },
        }),
      /REQUIREMENTS must be valid JSON/,
    );
  });

  void it('throws when a required mode field is missing (delegated to createAuthMiddleware)', () => {
    assert.throws(
      () => createAuthMiddlewareFromEnv({ env: { AUTH_MODE: 'jwt-hs256', AUTH_ISSUER: ISSUER } }),
      /secret/,
    );
  });
});
