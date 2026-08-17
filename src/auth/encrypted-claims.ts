import { TextDecoder, TextEncoder } from 'util';

import { CompactEncrypt, compactDecrypt } from 'jose';

/**
 * Encrypted claim blobs — confidential claims carried inside an otherwise readable JWT.
 *
 * A JWT is signed, not encrypted: anything in its payload is readable by whoever holds the
 * token, including a browser. To carry claims a frontend must NOT read (internal ids, price
 * tiers, entitlements), the issuer encrypts them into a **compact JWE** and stores that single
 * opaque string as one claim of the normal signed JWT. Holders of the shared secret — backend
 * services — decrypt it; everyone else sees ciphertext.
 *
 * The blob is `alg: dir` + `enc: A256GCM`: direct symmetric encryption under a 32-byte shared
 * key, authenticated (tampering fails decryption), and a plain RFC 7516 compact JWE, so a
 * consumer in any language can decrypt it without this library.
 *
 * This module holds both halves — the issuer side (`encryptClaims`) and the verification side
 * (`decryptClaims`) — because they must agree exactly on the header and key encoding. It lives
 * under `src/auth/` and, like the rest of this directory, imports only `jose` and node builtins.
 *
 * Note on threat model: the blob adds *confidentiality from the token holder*, not integrity —
 * the outer JWT signature already covers it. Anyone with the shared secret can decrypt, so use
 * one secret per audience rather than a single deployment-wide key.
 */

/** Key management algorithm of the claim blob: direct encryption under the shared key. */
export const ENCRYPTED_CLAIMS_ALG = 'dir';

/** Content encryption algorithm of the claim blob: AES-256-GCM (authenticated). */
export const ENCRYPTED_CLAIMS_ENC = 'A256GCM';

/** Claim that carries the blob when none is configured. */
export const DEFAULT_ENCRYPTED_CLAIM = 'enc';

/** Required shared-key length. A256GCM takes a 256-bit key. */
const KEY_BYTES = 32;

/** A parsed shared key, plus the optional `kid` advertised in the blob's header. */
export interface EncryptionKey {
  key: Uint8Array;
  /** Written to the JWE protected header, so a consumer can tell which key to reach for. */
  kid?: string;
}

function decodeHex(value: string): Uint8Array | null {
  if (!new RegExp(`^[0-9a-fA-F]{${KEY_BYTES * 2}}$`).test(value)) {
    return null;
  }

  return Uint8Array.from(Buffer.from(value, 'hex'));
}

function decodeBase64(value: string): Uint8Array | null {
  // Buffer's base64 decoder silently drops invalid characters, so screen the input first.
  // Both base64 and base64url alphabets are accepted (Buffer handles either).
  if (!/^[A-Za-z0-9+/\-_]+={0,2}$/.test(value)) {
    return null;
  }

  return Uint8Array.from(Buffer.from(value, 'base64'));
}

/**
 * Parse a configured shared secret into a 32-byte key.
 *
 * Accepts the two encodings a 32-byte key is normally handed around in: 64 hex characters, or
 * base64/base64url that decodes to exactly 32 bytes. Anything else throws — a short passphrase
 * is rejected rather than stretched, so the key strength is never silently weaker than it looks.
 *
 * @param label Name used in the error message (e.g. the config path the secret came from).
 */
export function parseEncryptionKey(secret: string, label = 'secret'): Uint8Array {
  const hex = decodeHex(secret);
  if (hex) {
    return hex;
  }

  const base64 = decodeBase64(secret);
  if (base64?.length === KEY_BYTES) {
    return base64;
  }

  throw new Error(
    `${label} must be a ${KEY_BYTES}-byte key encoded as base64 or hex ` +
      `(generate one with: openssl rand -base64 ${KEY_BYTES})`,
  );
}

/** Encrypt claims into a compact JWE string suitable for embedding as a single JWT claim. */
export async function encryptClaims(
  claims: Record<string, unknown>,
  key: EncryptionKey,
): Promise<string> {
  const protectedHeader: { alg: string; enc: string; kid?: string } = {
    alg: ENCRYPTED_CLAIMS_ALG,
    enc: ENCRYPTED_CLAIMS_ENC,
  };
  if (key.kid !== undefined) {
    protectedHeader.kid = key.kid;
  }

  return new CompactEncrypt(new TextEncoder().encode(JSON.stringify(claims)))
    .setProtectedHeader(protectedHeader)
    .encrypt(key.key);
}

/**
 * Decrypt a compact JWE claim blob back into an object.
 *
 * Accepts several keys so a secret can be rotated without downtime: they are tried in order,
 * which lets a consumer accept the previous key while issuers roll onto the new one. Throws if
 * no key decrypts the blob, if it was made with algorithms other than the pair above, or if the
 * plaintext is not a JSON object.
 */
export async function decryptClaims(
  jwe: string,
  keys: Uint8Array[],
): Promise<Record<string, unknown>> {
  if (keys.length === 0) {
    throw new Error('decryptClaims: at least one key is required');
  }

  let lastError: unknown;
  for (const key of keys) {
    try {
      const { plaintext } = await compactDecrypt(jwe, key, {
        keyManagementAlgorithms: [ENCRYPTED_CLAIMS_ALG],
        contentEncryptionAlgorithms: [ENCRYPTED_CLAIMS_ENC],
      });

      const parsed: unknown = JSON.parse(new TextDecoder().decode(plaintext));
      if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
        throw new Error('decrypted claims must be a JSON object');
      }

      return parsed as Record<string, unknown>;
    } catch (error) {
      lastError = error;
    }
  }

  throw new Error('Failed to decrypt claim blob with any configured key', { cause: lastError });
}

/**
 * Read an already-decrypted claim blob off a verified payload.
 *
 * After verification with `encryptedClaims` configured, the blob claim holds the decrypted
 * object rather than the ciphertext string. This is a typed accessor for that value; it returns
 * `undefined` when the claim is absent or still a string (i.e. was never decrypted).
 */
export function readEncryptedClaims(
  payload: Record<string, unknown>,
  claim: string = DEFAULT_ENCRYPTED_CLAIM,
): Record<string, unknown> | undefined {
  const value = payload[claim];
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return undefined;
  }

  return value as Record<string, unknown>;
}
