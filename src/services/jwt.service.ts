import { createPrivateKey, createPublicKey, sign } from 'crypto';
import { readFileSync } from 'fs';

import { config } from '../config/index';
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
  private readonly privateKey = createPrivateKey(loadPrivateKeyPem());
  private readonly jwk: JsonWebKey;

  constructor(kid: string) {
    this.kid = kid;
    this.jwk = createPublicKey(this.privateKey).export({ format: 'jwk' });
  }

  sign(claims: Record<string, unknown>, ttl: number, issuer: string): string {
    const now = Math.floor(Date.now() / 1000);
    const payload: Record<string, unknown> = {
      ...claims,
      iss: issuer,
      iat: now,
      exp: now + ttl,
    };

    const subject = payload.sub;
    if (typeof subject !== 'string' || subject.length === 0) {
      throw new HttpError(500, 'JWT payload must include a non-empty sub claim');
    }

    const header = {
      alg: 'RS256',
      typ: 'JWT',
      kid: this.kid,
    };

    const encodedHeader = encodeBase64Url(JSON.stringify(header));
    const encodedPayload = encodeBase64Url(JSON.stringify(payload));
    const signingInput = `${encodedHeader}.${encodedPayload}`;
    const signature = sign('RSA-SHA256', Buffer.from(signingInput), this.privateKey);

    return `${signingInput}.${encodeBase64Url(signature)}`;
  }

  getJwks(): JwksResponse {
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
