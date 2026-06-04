import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { after, before, describe, it } from 'node:test';

import type { Request, RequestHandler, Response } from 'express';
import { exportJWK, generateKeyPair, SignJWT, type JWK } from 'jose';

import { AuthError, createAuthMiddleware } from '../../src/auth/index';

const ISSUER = 'https://issuer.test';
const AUDIENCE = 'token-weaver-tests';
const SECRET = 'super-secret-value-with-enough-entropy';
const STATIC_TOKEN = 'static-shared-token-abc123';
const KID = 'test-key';

type RunResult = { error: unknown; req: Request };

/** Invoke a middleware against a mock request and resolve when next() fires. */
function runMiddleware(middleware: RequestHandler, authorization?: string): Promise<RunResult> {
  const headers = authorization === undefined ? {} : { authorization };
  const req = { headers } as unknown as Request;

  return new Promise((resolve) => {
    const next = (error?: unknown): void => {
      resolve({ error, req });
    };
    middleware(req, {} as Response, next);
  });
}

function assertUnauthorized(result: RunResult): void {
  assert.ok(result.error instanceof AuthError, 'expected an AuthError');
  assert.equal(result.error.status, 401);
}

// --- RS256 / JWKS fixtures: a tiny server serving the public JWK ----------------

let rsaPrivateKey: Awaited<ReturnType<typeof generateKeyPair>>['privateKey'];
let foreignKeyPair: Awaited<ReturnType<typeof generateKeyPair>>;
let jwksServer: Server;
let jwksUri: string;

before(async () => {
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  rsaPrivateKey = privateKey;
  foreignKeyPair = await generateKeyPair('RS256');

  const jwk: JWK = { ...(await exportJWK(publicKey)), kid: KID, alg: 'RS256', use: 'sig' };

  jwksServer = createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ keys: [jwk] }));
  });

  await new Promise<void>((resolve) => jwksServer.listen(0, '127.0.0.1', resolve));
  const { port } = jwksServer.address() as AddressInfo;
  jwksUri = `http://127.0.0.1:${port}/.well-known/jwks.json`;
});

after(async () => {
  await new Promise<void>((resolve, reject) =>
    jwksServer.close((err) => (err ? reject(err) : resolve())),
  );
});

function signRs256(claims: Record<string, unknown>, audience?: string): Promise<string> {
  const jwt = new SignJWT(claims)
    .setProtectedHeader({ alg: 'RS256', kid: KID })
    .setIssuer(ISSUER)
    .setSubject('user-1')
    .setExpirationTime('1h');
  if (audience !== undefined) {
    jwt.setAudience(audience);
  }
  return jwt.sign(rsaPrivateKey);
}

function signHs256(
  claims: Record<string, unknown>,
  options: { secret?: string; issuer?: string } = {},
): Promise<string> {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuer(options.issuer ?? ISSUER)
    .setSubject('user-1')
    .setExpirationTime('1h')
    .sign(Buffer.from(options.secret ?? SECRET));
}

// --- Construction-time validation -----------------------------------------------

void describe('createAuthMiddleware option validation', () => {
  void it('throws when jwks mode lacks jwksUri', () => {
    assert.throws(() => createAuthMiddleware({ mode: 'jwks', issuer: ISSUER }), /jwksUri/);
  });

  void it('throws when jwt modes lack issuer', () => {
    assert.throws(() => createAuthMiddleware({ mode: 'secret', secret: SECRET }), /issuer/);
  });

  void it('throws when secret mode lacks secret', () => {
    assert.throws(() => createAuthMiddleware({ mode: 'secret', issuer: ISSUER }), /secret/);
  });

  void it('throws when static mode lacks staticToken', () => {
    assert.throws(() => createAuthMiddleware({ mode: 'static' }), /staticToken/);
  });
});

// --- jwks mode (RS256) ----------------------------------------------------------

void describe('jwks mode', () => {
  void it('accepts a valid RS256 token and attaches the payload', async () => {
    let hookPayloadSub: unknown;
    const middleware = createAuthMiddleware({
      mode: 'jwks',
      issuer: ISSUER,
      jwksUri,
      onVerified: (payload) => {
        hookPayloadSub = payload.sub;
      },
    });

    const token = await signRs256({ scope: 'read' });
    const { error, req } = await runMiddleware(middleware, `Bearer ${token}`);

    assert.equal(error, undefined);
    assert.equal(req.jwtPayload?.sub, 'user-1');
    assert.equal(req.jwtPayload?.scope, 'read');
    assert.equal(hookPayloadSub, 'user-1');
  });

  void it('enforces audience when configured', async () => {
    const middleware = createAuthMiddleware({
      mode: 'jwks',
      issuer: ISSUER,
      audience: AUDIENCE,
      jwksUri,
    });

    const ok = await runMiddleware(middleware, `Bearer ${await signRs256({}, AUDIENCE)}`);
    assert.equal(ok.error, undefined);

    const wrong = await runMiddleware(middleware, `Bearer ${await signRs256({}, 'other-aud')}`);
    assertUnauthorized(wrong);
  });

  void it('rejects a token signed by an unknown key', async () => {
    const middleware = createAuthMiddleware({ mode: 'jwks', issuer: ISSUER, jwksUri });
    const foreign = await new SignJWT({})
      .setProtectedHeader({ alg: 'RS256', kid: KID })
      .setIssuer(ISSUER)
      .setSubject('user-1')
      .setExpirationTime('1h')
      .sign(foreignKeyPair.privateKey);

    assertUnauthorized(await runMiddleware(middleware, `Bearer ${foreign}`));
  });

  void it('rejects an HS256 token (wrong algorithm)', async () => {
    const middleware = createAuthMiddleware({ mode: 'jwks', issuer: ISSUER, jwksUri });
    assertUnauthorized(await runMiddleware(middleware, `Bearer ${await signHs256({})}`));
  });
});

// --- secret mode (HS256) --------------------------------------------------------

void describe('secret mode', () => {
  void it('accepts a valid HS256 token', async () => {
    const middleware = createAuthMiddleware({ mode: 'secret', issuer: ISSUER, secret: SECRET });
    const { error, req } = await runMiddleware(middleware, `Bearer ${await signHs256({})}`);

    assert.equal(error, undefined);
    assert.equal(req.jwtPayload?.sub, 'user-1');
  });

  void it('rejects a token signed with a different secret', async () => {
    const middleware = createAuthMiddleware({ mode: 'secret', issuer: ISSUER, secret: SECRET });
    const wrong = await signHs256({}, { secret: 'a-totally-different-secret-value' });

    assertUnauthorized(await runMiddleware(middleware, `Bearer ${wrong}`));
  });

  void it('rejects a wrong issuer', async () => {
    const middleware = createAuthMiddleware({ mode: 'secret', issuer: ISSUER, secret: SECRET });
    const wrong = await signHs256({}, { issuer: 'https://evil.test' });

    assertUnauthorized(await runMiddleware(middleware, `Bearer ${wrong}`));
  });

  void it('rejects an RS256 token (wrong algorithm)', async () => {
    const middleware = createAuthMiddleware({ mode: 'secret', issuer: ISSUER, secret: SECRET });
    assertUnauthorized(await runMiddleware(middleware, `Bearer ${await signRs256({})}`));
  });
});

// --- static mode ----------------------------------------------------------------

void describe('static mode', () => {
  void it('accepts the matching token and runs onVerified', async () => {
    let called = false;
    const middleware = createAuthMiddleware({
      mode: 'static',
      staticToken: STATIC_TOKEN,
      onVerified: () => {
        called = true;
      },
    });

    const { error, req } = await runMiddleware(middleware, `Bearer ${STATIC_TOKEN}`);
    assert.equal(error, undefined);
    assert.deepEqual(req.jwtPayload, {});
    assert.equal(called, true);
  });

  void it('rejects a non-matching token', async () => {
    const middleware = createAuthMiddleware({ mode: 'static', staticToken: STATIC_TOKEN });
    assertUnauthorized(await runMiddleware(middleware, 'Bearer not-the-token'));
  });
});

// --- bearer extraction (mode-agnostic) ------------------------------------------

void describe('bearer extraction', () => {
  void it('rejects a missing Authorization header', async () => {
    const middleware = createAuthMiddleware({ mode: 'static', staticToken: STATIC_TOKEN });
    assertUnauthorized(await runMiddleware(middleware, undefined));
  });

  void it('rejects a malformed Authorization header', async () => {
    const middleware = createAuthMiddleware({ mode: 'static', staticToken: STATIC_TOKEN });
    assertUnauthorized(await runMiddleware(middleware, STATIC_TOKEN));
  });
});
