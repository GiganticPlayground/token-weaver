import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import type { Request, RequestHandler, Response } from 'express';
import { SignJWT } from 'jose';

import { AuthError, ForbiddenError, createAuthMiddleware } from '../../src/auth/index';

const ISSUER = 'https://issuer.test';
const SECRET = 'authz-secret-value-with-enough-entropy';

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

function secretAuth(extra: Partial<Parameters<typeof createAuthMiddleware>[0]>): RequestHandler {
  return createAuthMiddleware({ mode: 'secret', issuer: ISSUER, secret: SECRET, ...extra });
}

function assertForbidden(result: RunResult): void {
  assert.ok(result.error instanceof ForbiddenError, 'expected a ForbiddenError');
  assert.equal(result.error.status, 403);
}

function assertOk(result: RunResult): void {
  assert.equal(result.error, undefined);
}

// --- requirements ---------------------------------------------------------------

void describe('requirements', () => {
  void it('passes when the scope claim includes the required value', async () => {
    const mw = secretAuth({ requirements: [{ type: 'scope', value: 'nexus:read' }] });
    const token = await signHs256({ scope: 'nexus:read other:thing' });
    const result = await runMiddleware(mw, { authorization: `Bearer ${token}` });
    assertOk(result);
    assert.equal(result.req.jwtPayload?.sub, 'user-1');
  });

  void it('rejects with 403 when the scope is missing', async () => {
    const mw = secretAuth({ requirements: [{ type: 'scope', value: 'nexus:read' }] });
    const token = await signHs256({ scope: 'other:thing' });
    assertForbidden(await runMiddleware(mw, { authorization: `Bearer ${token}` }));
  });

  void it('supports claim_includes against an array claim', async () => {
    const mw = secretAuth({
      requirements: [{ type: 'claim_includes', claim: 'permissions', value: 'data:read' }],
    });
    const token = await signHs256({ permissions: ['data:read', 'data:write'] });
    assertOk(await runMiddleware(mw, { authorization: `Bearer ${token}` }));
  });

  void it('rejects with 403 when claim_includes is not satisfied', async () => {
    const mw = secretAuth({
      requirements: [{ type: 'claim_includes', claim: 'permissions', value: 'data:read' }],
    });
    const token = await signHs256({ permissions: ['data:write'] });
    assertForbidden(await runMiddleware(mw, { authorization: `Bearer ${token}` }));
  });
});

// --- paths (whitelist / blacklist) ----------------------------------------------

void describe('paths', () => {
  void it('allows a path matching the whitelist claim', async () => {
    const mw = secretAuth({ paths: { whitelistClaim: 'whitelist' } });
    const token = await signHs256({ whitelist: ['/nexus/*'] });
    assertOk(await runMiddleware(mw, { authorization: `Bearer ${token}`, path: '/nexus/data' }));
  });

  void it('rejects a path not in the whitelist with 403', async () => {
    const mw = secretAuth({ paths: { whitelistClaim: 'whitelist' } });
    const token = await signHs256({ whitelist: ['/nexus/*'] });
    assertForbidden(
      await runMiddleware(mw, { authorization: `Bearer ${token}`, path: '/admin/data' }),
    );
  });

  void it('leaves the path unrestricted when the token has no whitelist claim', async () => {
    const mw = secretAuth({ paths: { whitelistClaim: 'whitelist' } });
    const token = await signHs256({});
    assertOk(await runMiddleware(mw, { authorization: `Bearer ${token}`, path: '/anything' }));
  });

  void it('lets the blacklist win over the whitelist', async () => {
    const mw = secretAuth({ paths: { whitelistClaim: 'whitelist', blacklistClaim: 'blacklist' } });
    const token = await signHs256({ whitelist: ['/nexus/*'], blacklist: ['/nexus/admin'] });
    assertForbidden(
      await runMiddleware(mw, { authorization: `Bearer ${token}`, path: '/nexus/admin' }),
    );
  });

  void it('strips pathPrefix before matching', async () => {
    const mw = secretAuth({ paths: { pathPrefix: '/api', whitelistClaim: 'whitelist' } });
    const token = await signHs256({ whitelist: ['/nexus/data'] });
    assertOk(
      await runMiddleware(mw, {
        authorization: `Bearer ${token}`,
        baseUrl: '/api',
        path: '/nexus/data',
      }),
    );
  });
});

// --- mode / status-code interactions --------------------------------------------

void describe('authorization interactions', () => {
  void it('skips authorization entirely in static mode', async () => {
    const mw = createAuthMiddleware({
      mode: 'static',
      staticToken: 'fixed-token',
      requirements: [{ type: 'scope', value: 'nexus:read' }],
      paths: { whitelistClaim: 'whitelist' },
    });
    const result = await runMiddleware(mw, { authorization: 'Bearer fixed-token', path: '/x' });
    assertOk(result);
    assert.deepEqual(result.req.jwtPayload, {});
  });

  void it('fails authentication (401) before authorization runs', async () => {
    const mw = secretAuth({ requirements: [{ type: 'scope', value: 'nexus:read' }] });
    const forged = await new SignJWT({ scope: 'nexus:read' })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuer(ISSUER)
      .setSubject('user-1')
      .setExpirationTime('1h')
      .sign(Buffer.from('a-different-secret-entirely-here'));

    const result = await runMiddleware(mw, { authorization: `Bearer ${forged}` });
    assert.ok(result.error instanceof AuthError, 'expected AuthError');
    assert.equal(result.error.status, 401);
  });
});
