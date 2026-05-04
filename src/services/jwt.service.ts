import { createHmac, createPrivateKey, createPublicKey, sign, type JsonWebKey, type KeyObject } from 'crypto';
import { readFileSync } from 'fs';

import { config } from '../config/index';
import type { JwtConfig } from '../config/token-weaver.config';
import { HttpError } from '../utils/http-error';

export interface JwksResponse {
  keys: Array<JsonWebKey & { use: string; alg: string; kid: string }>;
}

function encodeBase64Url(value: Buffer | string): string {
  return Buffer.from(value)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function loadPrivateKeyPem(): string {
  if (config.TOKEN_WEAVER_PRIVATE_KEY) {
    return config.TOKEN_WEAVER_PRIVATE_KEY;
  }

  if (config.TOKEN_WEAVER_PRIVATE_KEY_PATH) {
    return readFileSync(config.TOKEN_WEAVER_PRIVATE_KEY_PATH, 'utf8');
  }

  throw new HttpError(
    500,
    'A signing key is required. Set TOKEN_WEAVER_PRIVATE_KEY or TOKEN_WEAVER_PRIVATE_KEY_PATH.',
  );
}

export class JwtService {
  private readonly kid: string;
  private readonly privateKey: KeyObject | null;
  private readonly jwk: JsonWebKey | null;

  constructor(kid: string, needsRsa: boolean) {
    this.kid = kid;
    if (needsRsa) {
      this.privateKey = createPrivateKey(loadPrivateKeyPem());
      this.jwk = createPublicKey(this.privateKey).export({ format: 'jwk' });
    } else {
      this.privateKey = null;
      this.jwk = null;
    }
  }

  sign(claims: Record<string, unknown>, jwt: JwtConfig): string {
    const now = Math.floor(Date.now() / 1000);
    const payload: Record<string, unknown> = {
      ...claims,
      iss: jwt.issuer,
      iat: now,
      exp: now + jwt.ttl,
    };

    const subject = payload.sub;
    if (typeof subject !== 'string' || subject.length === 0) {
      throw new HttpError(500, 'JWT payload must include a non-empty sub claim');
    }

    if (jwt.algorithm === 'HS256') {
      if (!jwt.secret) {
        throw new HttpError(500, 'HS256 signing requested but no secret is configured');
      }
      const header = { alg: 'HS256' as const, typ: 'JWT' as const };
      const encodedHeader = encodeBase64Url(JSON.stringify(header));
      const encodedPayload = encodeBase64Url(JSON.stringify(payload));
      const signingInput = `${encodedHeader}.${encodedPayload}`;
      const signature = createHmac('sha256', jwt.secret).update(signingInput).digest();
      return `${signingInput}.${encodeBase64Url(signature)}`;
    }

    if (!this.privateKey) {
      throw new HttpError(500, 'RS256 signing requested but no private key is loaded');
    }
    const header = { alg: 'RS256' as const, typ: 'JWT' as const, kid: this.kid };
    const encodedHeader = encodeBase64Url(JSON.stringify(header));
    const encodedPayload = encodeBase64Url(JSON.stringify(payload));
    const signingInput = `${encodedHeader}.${encodedPayload}`;
    const signature = sign('RSA-SHA256', Buffer.from(signingInput), this.privateKey);
    return `${signingInput}.${encodeBase64Url(signature)}`;
  }

  getJwks(): JwksResponse {
    if (!this.jwk) {
      return { keys: [] };
    }

    return {
      keys: [
        {
          ...this.jwk,
          use: 'sig',
          alg: 'RS256',
          kid: this.kid,
        },
      ],
    };
  }
}
