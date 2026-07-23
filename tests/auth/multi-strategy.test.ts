import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import type { Request, RequestHandler, Response } from 'express';
import { SignJWT } from 'jose';

import { AuthError, ForbiddenError, createAuthMiddleware } from '../../src/auth/index';

const ISSUER = 'https://issuer.test';
const SECRET = 'multi-strategy-secret-with-enough-entropy';
const STATIC_TOKEN = 'internal-service-token-abc123';

type RunResult = { error: unknown; req: Request };

function runMiddleware(
  middleware: RequestHandler,
  reqInit: { authorization?: string; baseUrl?: string; path?: string },
): Promise<RunResult> {
  const headers =
    reqInit.authorization === undefined ? {} : { authorization: reqInit.authorization };
  const req = {
    headers,
    baseUrl: reqInit.baseUrl ?? '',
    path: reqInit.path ?? '/',
  } as unknown as Request;

  return new Promise((resolve) => {
    const next = (error?: unknown): void => {
      resolve({ error, req });
    };
    middleware(req, {} as Response, next);
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

function assertOk(result: RunResult): void {
  assert.equal(result.error, undefined);
}

function assertUnauthorized(result: RunResult): void {
  assert.ok(result.error instanceof AuthError, 'expected an AuthError');
  assert.equal(result.error.status, 401);
}

function assertForbidden(result: RunResult): void {
  assert.ok(result.error instanceof ForbiddenError, 'expected a ForbiddenError');
  assert.equal(result.error.status, 403);
}

// Static token first, then an HS256 JWT strategy — a common real setup: internal
// service-to-service calls use the static token, clients use JWTs.
function staticThenJwt(): RequestHandler {
  return createAuthMiddleware({
    strategies: [
      { mode: 'static', staticToken: STATIC_TOKEN },
      { mode: 'jwt-hs256', issuer: ISSUER, secret: SECRET },
    ],
  });
}

void describe('multi-strategy — tries each in order', () => {
  void it('accepts via the first strategy (static token)', async () => {
    const result = await runMiddleware(staticThenJwt(), {
      authorization: `Bearer ${STATIC_TOKEN}`,
    });
    assertOk(result);
    assert.deepEqual(result.req.jwtPayload, {});
  });

  void it('falls through to the JWT strategy when the static token does not match', async () => {
    const token = await signHs256({ scope: 'qodi:decrypt' });
    const result = await runMiddleware(staticThenJwt(), { authorization: `Bearer ${token}` });
    assertOk(result);
    assert.equal(result.req.jwtPayload?.sub, 'user-1');
  });

  void it('rejects with 401 when no strategy accepts the token', async () => {
    const result = await runMiddleware(staticThenJwt(), { authorization: 'Bearer not-a-token' });
    assertUnauthorized(result);
  });

  void it('runs onVerified once, with the winning payload', async () => {
    let seen: unknown;
    const mw = createAuthMiddleware({
      strategies: [
        { mode: 'static', staticToken: STATIC_TOKEN },
        { mode: 'jwt-hs256', issuer: ISSUER, secret: SECRET },
      ],
      onVerified: (payload) => {
        seen = payload;
      },
    });
    const token = await signHs256({ scope: 'a' });
    const result = await runMiddleware(mw, { authorization: `Bearer ${token}` });
    assertOk(result);
    assert.equal((seen as { sub?: string }).sub, 'user-1');
  });

  void it('prefers a 403 (authorized-but-forbidden) over a 401 across strategies', async () => {
    // Strategy 1 (static) rejects the JWT bearer with 401; strategy 2 verifies the JWT but the
    // scope requirement fails → 403. The 403 should win.
    const mw = createAuthMiddleware({
      strategies: [
        { mode: 'static', staticToken: STATIC_TOKEN },
        {
          mode: 'jwt-hs256',
          issuer: ISSUER,
          secret: SECRET,
          requirements: [{ type: 'scope', value: 'qodi:decrypt' }],
        },
      ],
    });
    const token = await signHs256({ scope: 'something:else' });
    assertForbidden(await runMiddleware(mw, { authorization: `Bearer ${token}` }));
  });

  void it('throws synchronously on an empty strategies array', () => {
    assert.throws(() => createAuthMiddleware({ strategies: [] }), /non-empty array/);
  });
});

// --- static-token inline path scoping -------------------------------------------

void describe('static token — inline path allow/deny', () => {
  void it('allows a whitelisted path', async () => {
    const mw = createAuthMiddleware({
      mode: 'static',
      staticToken: STATIC_TOKEN,
      paths: { whitelist: ['/qodi/decrypt'] },
    });
    assertOk(
      await runMiddleware(mw, { authorization: `Bearer ${STATIC_TOKEN}`, path: '/qodi/decrypt' }),
    );
  });

  void it('denies a non-whitelisted path with 403', async () => {
    const mw = createAuthMiddleware({
      mode: 'static',
      staticToken: STATIC_TOKEN,
      paths: { whitelist: ['/qodi/decrypt'] },
    });
    assertForbidden(
      await runMiddleware(mw, { authorization: `Bearer ${STATIC_TOKEN}`, path: '/qodi/publickey' }),
    );
  });

  void it('lets an inline blacklist win over the whitelist', async () => {
    const mw = createAuthMiddleware({
      mode: 'static',
      staticToken: STATIC_TOKEN,
      paths: { whitelist: ['/qodi/*'], blacklist: ['/qodi/admin'] },
    });
    assertForbidden(
      await runMiddleware(mw, { authorization: `Bearer ${STATIC_TOKEN}`, path: '/qodi/admin' }),
    );
    assertOk(
      await runMiddleware(mw, { authorization: `Bearer ${STATIC_TOKEN}`, path: '/qodi/decrypt' }),
    );
  });

  void it('is unrestricted when no paths are configured', async () => {
    const mw = createAuthMiddleware({ mode: 'static', staticToken: STATIC_TOKEN });
    assertOk(
      await runMiddleware(mw, { authorization: `Bearer ${STATIC_TOKEN}`, path: '/anything' }),
    );
  });

  void it('strips pathPrefix before matching the inline whitelist', async () => {
    const mw = createAuthMiddleware({
      mode: 'static',
      staticToken: STATIC_TOKEN,
      paths: { pathPrefix: '/api', whitelist: ['/qodi/decrypt'] },
    });
    assertOk(
      await runMiddleware(mw, {
        authorization: `Bearer ${STATIC_TOKEN}`,
        baseUrl: '/api',
        path: '/qodi/decrypt',
      }),
    );
  });
});
