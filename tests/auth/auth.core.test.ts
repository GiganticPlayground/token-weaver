import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { TextEncoder } from 'node:util';

import { SignJWT } from 'jose';

import {
  authenticate,
  AuthError,
  checkPathAccess,
  compileAuth,
  extractBearerToken,
  ForbiddenError,
} from '../../src/auth/index';

const ISSUER = 'https://issuer.test';
const SECRET = 'super-secret-value-with-enough-entropy';
const STATIC_TOKEN = 'static-shared-token-abc123';

async function signHs256(claims: Record<string, unknown> = {}): Promise<string> {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuer(ISSUER)
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(new TextEncoder().encode(SECRET));
}

void describe('extractBearerToken', () => {
  void it('extracts the token from a Bearer header', () => {
    assert.equal(extractBearerToken('Bearer abc'), 'abc');
  });

  void it('throws AuthError on a missing header', () => {
    assert.throws(() => extractBearerToken(undefined), AuthError);
  });

  void it('throws AuthError on a non-bearer scheme', () => {
    assert.throws(() => extractBearerToken('Basic abc'), AuthError);
  });
});

void describe('authenticate (framework-agnostic)', () => {
  void it('accepts a valid static token and returns an empty payload', async () => {
    const payload = await authenticate(
      { authorizationHeader: `Bearer ${STATIC_TOKEN}` },
      { mode: 'static', staticToken: STATIC_TOKEN },
    );
    assert.deepEqual(payload, {});
  });

  void it('rejects a wrong static token with a 401 AuthError', async () => {
    await assert.rejects(
      authenticate({ authorizationHeader: 'Bearer nope' }, { mode: 'static', staticToken: STATIC_TOKEN }),
      AuthError,
    );
  });

  void it('verifies an HS256 token and returns its claims', async () => {
    const token = await signHs256({ sub: 'user-1' });
    const payload = await authenticate(
      { authorizationHeader: `Bearer ${token}` },
      { mode: 'jwt-hs256', secret: SECRET, issuer: ISSUER },
    );
    assert.equal(payload.sub, 'user-1');
  });

  void it('enforces inline path whitelists (403 on a non-matching path)', async () => {
    const token = await signHs256();
    const options = {
      mode: 'jwt-hs256' as const,
      secret: SECRET,
      issuer: ISSUER,
      paths: { whitelist: ['svc/read*'] },
    };

    const payload = await authenticate(
      { authorizationHeader: `Bearer ${token}`, path: 'svc/readThing' },
      options,
    );
    assert.ok(payload);

    await assert.rejects(
      authenticate({ authorizationHeader: `Bearer ${token}`, path: 'svc/writeThing' }, options),
      ForbiddenError,
    );
  });

  void it('fails closed when paths are configured but no path is provided', async () => {
    const token = await signHs256();
    await assert.rejects(
      authenticate(
        { authorizationHeader: `Bearer ${token}` },
        { mode: 'jwt-hs256', secret: SECRET, issuer: ISSUER, paths: { whitelist: ['*'] } },
      ),
      ForbiddenError,
    );
  });

  void it('reads claim-carried path lists (whitelistClaim/blacklistClaim)', async () => {
    const token = await signHs256({ allow: ['svc/*'], deny: ['svc/admin'] });
    const options = {
      mode: 'jwt-hs256' as const,
      secret: SECRET,
      issuer: ISSUER,
      paths: { whitelistClaim: 'allow', blacklistClaim: 'deny' },
    };

    assert.ok(await authenticate({ authorizationHeader: `Bearer ${token}`, path: 'svc/data' }, options));
    await assert.rejects(
      authenticate({ authorizationHeader: `Bearer ${token}`, path: 'svc/admin' }, options),
      ForbiddenError,
    );
  });

  void it('prefers a 403 failure over a 401 across multiple strategies', async () => {
    const token = await signHs256();
    await assert.rejects(
      authenticate(
        { authorizationHeader: `Bearer ${token}`, path: 'svc/blocked' },
        {
          strategies: [
            { mode: 'static', staticToken: STATIC_TOKEN }, // 401 for this token
            {
              mode: 'jwt-hs256',
              secret: SECRET,
              issuer: ISSUER,
              paths: { whitelist: ['svc/allowed'] }, // verifies, then 403
            },
          ],
        },
      ),
      ForbiddenError,
    );
  });
});

void describe('compileAuth', () => {
  void it('returns a reusable authenticator', async () => {
    const compiled = compileAuth({ mode: 'static', staticToken: STATIC_TOKEN });
    assert.deepEqual(await compiled({ authorizationHeader: `Bearer ${STATIC_TOKEN}` }), {});
    await assert.rejects(compiled({ authorizationHeader: 'Bearer nope' }), AuthError);
  });
});

void describe('checkPathAccess', () => {
  void it('anchors glob patterns (no substring over-matching)', () => {
    const paths = { whitelist: ['svc/read'] };
    assert.equal(checkPathAccess('svc/read', paths), true);
    assert.equal(checkPathAccess('svc/readEverything', paths), false);
    assert.equal(checkPathAccess('svc/read/sub', paths), false);
  });

  void it('supports glob wildcards and blacklist-wins', () => {
    const paths = { whitelist: ['svc/*'], blacklist: ['svc/admin'] };
    assert.equal(checkPathAccess('svc/data', paths), true);
    assert.equal(checkPathAccess('svc/admin', paths), false);
  });

  void it('denies everything on an empty whitelist', () => {
    assert.equal(checkPathAccess('anything', { whitelist: [] }), false);
  });

  void it('escapes regex metacharacters in patterns', () => {
    const paths = { whitelist: ['svc/a.b'] };
    assert.equal(checkPathAccess('svc/a.b', paths), true);
    assert.equal(checkPathAccess('svc/aXb', paths), false);
  });
});
