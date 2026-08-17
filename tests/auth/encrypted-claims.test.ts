import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import type { Request, RequestHandler, Response } from 'express';
import { SignJWT } from 'jose';

import {
  AuthError,
  createAuthMiddleware,
  decryptClaims,
  encryptClaims,
  parseEncryptionKey,
  readEncryptedClaims,
} from '../../src/auth/index';

const ISSUER = 'https://issuer.test';
const SECRET = 'encrypted-claims-secret-with-entropy';
const KEY_A = Buffer.from('key-a-key-a-key-a-key-a-key-a-32').toString('base64');
const KEY_B = Buffer.from('key-b-key-b-key-b-key-b-key-b-32').toString('base64');

type RunResult = { error: unknown; req: Request };

function runMiddleware(middleware: RequestHandler, authorization?: string): Promise<RunResult> {
  const req = {
    headers: authorization === undefined ? {} : { authorization },
    baseUrl: '',
    path: '/',
  } as unknown as Request;

  return new Promise((resolve) => {
    middleware(req, {} as Response, (error?: unknown) => {
      resolve({ error, req });
    });
  });
}

async function signWithBlob(
  claims: Record<string, unknown>,
  blobKey: string,
  blobClaim = 'enc',
): Promise<string> {
  const blob = await encryptClaims(claims, { key: parseEncryptionKey(blobKey) });
  return new SignJWT({ [blobClaim]: blob })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuer(ISSUER)
    .setSubject('user-1')
    .setExpirationTime('1h')
    .sign(Buffer.from(SECRET));
}

// --- key parsing ----------------------------------------------------------------

void describe('parseEncryptionKey', () => {
  void it('accepts a 32-byte base64 key', () => {
    assert.equal(parseEncryptionKey(KEY_A).length, 32);
  });

  void it('accepts a 32-byte base64url key', () => {
    const base64url = Buffer.from('key-a-key-a-key-a-key-a-key-a-32').toString('base64url');
    assert.deepEqual(parseEncryptionKey(base64url), parseEncryptionKey(KEY_A));
  });

  void it('accepts a 64-character hex key', () => {
    const hex = Buffer.from('key-a-key-a-key-a-key-a-key-a-32').toString('hex');
    assert.deepEqual(parseEncryptionKey(hex), parseEncryptionKey(KEY_A));
  });

  void it('rejects a key of the wrong length', () => {
    assert.throws(
      () => parseEncryptionKey(Buffer.from('too-short').toString('base64'), 'my.secret'),
      /my\.secret must be a 32-byte key/,
    );
  });

  void it('rejects a passphrase rather than stretching it', () => {
    assert.throws(() => parseEncryptionKey('correct horse battery staple'), /32-byte key/);
  });
});

// --- round trip -----------------------------------------------------------------

void describe('encryptClaims / decryptClaims', () => {
  const key = parseEncryptionKey(KEY_A);

  void it('round-trips an object through a compact JWE', async () => {
    const claims = { internalId: 42, tier: 'gold', tags: ['a', 'b'], nested: { ok: true } };
    const blob = await encryptClaims(claims, { key });

    assert.equal(blob.split('.').length, 5);
    assert.deepEqual(await decryptClaims(blob, [key]), claims);
  });

  void it('hides the plaintext in the blob', async () => {
    const blob = await encryptClaims({ tier: 'platinum' }, { key });
    assert.ok(!blob.includes('platinum'));
    assert.ok(!Buffer.from(blob).toString('utf8').includes('platinum'));
  });

  void it('writes the optional kid into the protected header', async () => {
    const blob = await encryptClaims({ a: 1 }, { key, kid: 'enc-key-1' });
    const header = JSON.parse(Buffer.from(blob.split('.')[0]!, 'base64url').toString('utf8')) as {
      alg: string;
      enc: string;
      kid: string;
    };

    assert.deepEqual(header, { alg: 'dir', enc: 'A256GCM', kid: 'enc-key-1' });
  });

  void it('fails with the wrong key', async () => {
    const blob = await encryptClaims({ a: 1 }, { key });
    await assert.rejects(
      decryptClaims(blob, [parseEncryptionKey(KEY_B)]),
      /Failed to decrypt claim blob/,
    );
  });

  void it('tries every key so a secret can be rotated', async () => {
    const blob = await encryptClaims({ a: 1 }, { key: parseEncryptionKey(KEY_B) });
    assert.deepEqual(await decryptClaims(blob, [key, parseEncryptionKey(KEY_B)]), { a: 1 });
  });

  void it('detects tampering with the ciphertext', async () => {
    const blob = await encryptClaims({ role: 'user' }, { key });
    const parts = blob.split('.');
    // Flip the last character of the ciphertext segment.
    const ciphertext = parts[3]!;
    parts[3] = `${ciphertext.slice(0, -1)}${ciphertext.at(-1) === 'A' ? 'B' : 'A'}`;

    await assert.rejects(decryptClaims(parts.join('.'), [key]), /Failed to decrypt claim blob/);
  });

  void it('rejects a blob whose plaintext is not a JSON object', async () => {
    const blob = await encryptClaims(
      ['not', 'an', 'object'] as unknown as Record<string, unknown>,
      {
        key,
      },
    );
    await assert.rejects(decryptClaims(blob, [key]), /Failed to decrypt claim blob/);
  });
});

// --- verification-side integration ----------------------------------------------

void describe('middleware with encryptedClaims', () => {
  void it('replaces the blob claim with the decrypted object', async () => {
    const token = await signWithBlob({ internalId: 'i-1', tier: 'gold' }, KEY_A);
    const mw = createAuthMiddleware({
      mode: 'jwt-hs256',
      issuer: ISSUER,
      secret: SECRET,
      encryptedClaims: { secret: KEY_A },
    });

    const { error, req } = await runMiddleware(mw, `Bearer ${token}`);
    assert.equal(error, undefined);
    assert.deepEqual(req.jwtPayload?.enc, { internalId: 'i-1', tier: 'gold' });
    assert.deepEqual(readEncryptedClaims(req.jwtPayload ?? {}), {
      internalId: 'i-1',
      tier: 'gold',
    });
  });

  void it('reads the blob from a custom claim name', async () => {
    const token = await signWithBlob({ secretValue: 1 }, KEY_A, 'private');
    const mw = createAuthMiddleware({
      mode: 'jwt-hs256',
      issuer: ISSUER,
      secret: SECRET,
      encryptedClaims: { secret: KEY_A, claim: 'private' },
    });

    const { error, req } = await runMiddleware(mw, `Bearer ${token}`);
    assert.equal(error, undefined);
    assert.deepEqual(req.jwtPayload?.private, { secretValue: 1 });
  });

  void it('accepts either key during a rotation', async () => {
    const mw = createAuthMiddleware({
      mode: 'jwt-hs256',
      issuer: ISSUER,
      secret: SECRET,
      encryptedClaims: { secret: [KEY_B, KEY_A] },
    });

    for (const key of [KEY_A, KEY_B]) {
      const token = await signWithBlob({ from: key }, key);
      const { error } = await runMiddleware(mw, `Bearer ${token}`);
      assert.equal(error, undefined);
    }
  });

  void it('rejects with 401 when the blob cannot be decrypted', async () => {
    const token = await signWithBlob({ a: 1 }, KEY_B);
    const mw = createAuthMiddleware({
      mode: 'jwt-hs256',
      issuer: ISSUER,
      secret: SECRET,
      encryptedClaims: { secret: KEY_A },
    });

    const { error } = await runMiddleware(mw, `Bearer ${token}`);
    assert.ok(error instanceof AuthError);
    assert.equal(error.status, 401);
  });

  void it('rejects with 401 when a required blob is missing', async () => {
    const token = await new SignJWT({})
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuer(ISSUER)
      .setSubject('user-1')
      .setExpirationTime('1h')
      .sign(Buffer.from(SECRET));

    const mw = createAuthMiddleware({
      mode: 'jwt-hs256',
      issuer: ISSUER,
      secret: SECRET,
      encryptedClaims: { secret: KEY_A },
    });

    const { error } = await runMiddleware(mw, `Bearer ${token}`);
    assert.ok(error instanceof AuthError);
    assert.match(error.message, /missing the encrypted claim/);
  });

  void it('allows a missing blob when it is not required', async () => {
    const token = await new SignJWT({})
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuer(ISSUER)
      .setSubject('user-1')
      .setExpirationTime('1h')
      .sign(Buffer.from(SECRET));

    const mw = createAuthMiddleware({
      mode: 'jwt-hs256',
      issuer: ISSUER,
      secret: SECRET,
      encryptedClaims: { secret: KEY_A, required: false },
    });

    const { error, req } = await runMiddleware(mw, `Bearer ${token}`);
    assert.equal(error, undefined);
    assert.equal(req.jwtPayload?.enc, undefined);
  });

  void it('fails fast on a malformed secret', () => {
    assert.throws(
      () =>
        createAuthMiddleware({
          mode: 'jwt-hs256',
          issuer: ISSUER,
          secret: SECRET,
          encryptedClaims: { secret: 'not-a-key' },
        }),
      /encryptedClaims\.secret\[0\] must be a 32-byte key/,
    );
  });

  void it('does not satisfy requirements from a scope hidden inside the blob', async () => {
    const token = await signWithBlob({ scope: ['svc:read'] }, KEY_A);
    // The blob is decrypted before authorization, but requirements read top-level claims — so a
    // scope hidden in the blob does NOT satisfy them.
    const mw = createAuthMiddleware({
      mode: 'jwt-hs256',
      issuer: ISSUER,
      secret: SECRET,
      encryptedClaims: { secret: KEY_A },
      requirements: [{ type: 'scope', value: 'svc:read' }],
    });

    const { error } = await runMiddleware(mw, `Bearer ${token}`);
    assert.ok(error instanceof Error);
    assert.equal((error as { status?: number }).status, 403);
  });
});
