import type { Request } from 'express';

import { JwtService } from './jwt.service';
import { compileAuth, extractBearerToken, type CompiledAuth } from '../auth/auth.core';
import { encryptClaims, parseEncryptionKey } from '../auth/encrypted-claims';
import { config } from '../config/index';
import type {
  DelegatedStrategyConfig,
  DirectCredential,
  ErrorMappingConfig,
  InboundAuthConfig,
  JwtStrategyConfig,
  StrategyConfig,
  TokenWeaverConfig,
} from '../config/token-weaver.config';
import { HttpError, UpstreamUnavailableError } from '../utils/http-error';
import { evaluateCondition, resolvePath } from '../utils/path-expression';
import { httpRequest, logger } from '../utils/index';

export interface AuthSuccessPayload {
  token: string;
  expires_in: number;
}

type RequestContext = {
  request: {
    body: unknown;
    headers: Record<string, string | string[] | undefined>;
    query: Record<string, unknown>;
    params: Record<string, unknown>;
    path: string;
    method: string;
    /** Verified upstream claims - only set for the 'jwt' exchange strategy. */
    jwt?: Record<string, unknown>;
  };
};

type UpstreamContext = Record<string, unknown>;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function toComparableString(value: unknown): string | undefined {
  if (typeof value === 'string') {
    return value;
  }

  if (typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }

  return undefined;
}

function mapValue(value: unknown, context: Record<string, unknown>): unknown {
  if (typeof value === 'string' && value.startsWith('$')) {
    return resolvePath(value, context);
  }

  if (Array.isArray(value)) {
    return value.map((entry) => mapValue(entry, context));
  }

  if (isPlainObject(value)) {
    return Object.fromEntries(
      Object.entries(value).map(([key, currentValue]) => [key, mapValue(currentValue, context)]),
    );
  }

  return value;
}

function normalizeHeaders(
  headers: Request['headers'],
): Record<string, string | string[] | undefined> {
  return Object.fromEntries(
    Object.entries(headers).map(([key, value]) => [key.toLowerCase(), value]),
  );
}

function getHeaderValue(
  headers: Record<string, string | string[] | undefined>,
  headerName: string,
): string | undefined {
  const value = headers[headerName.toLowerCase()];
  if (Array.isArray(value)) {
    return value[0];
  }

  return value;
}

function buildRequestContext(req: Request, verifiedJwt?: Record<string, unknown>): RequestContext {
  return {
    request: {
      body: req.body,
      headers: normalizeHeaders(req.headers),
      query: req.query as Record<string, unknown>,
      params: req.params as Record<string, unknown>,
      path: req.path,
      method: req.method,
      // Present only for the 'jwt' exchange strategy, so mappings can read the verified
      // upstream claims as $.request.jwt.<claim>.
      ...(verifiedJwt ? { jwt: verifiedJwt } : {}),
    },
  };
}

function assertObjectBody(body: unknown): void {
  if (!isPlainObject(body)) {
    throw new HttpError(400, 'Request body must be a JSON object');
  }
}

function verifyInboundAuth(configValue: InboundAuthConfig | undefined, req: Request): void {
  if (!configValue || configValue.type === 'none') {
    return;
  }

  const headers = normalizeHeaders(req.headers);
  if (configValue.type === 'api_key') {
    const headerName = configValue.header ?? 'x-api-key';
    const actualValue = getHeaderValue(headers, headerName);
    if (!actualValue || actualValue !== configValue.key) {
      throw new HttpError(401, 'Invalid inbound API key');
    }
    return;
  }

  const authorizationHeader = getHeaderValue(headers, configValue.header ?? 'authorization');
  const expectedToken = configValue.token;
  if (!authorizationHeader || !expectedToken) {
    throw new HttpError(401, 'Invalid inbound bearer token');
  }

  const [scheme, token] = authorizationHeader.split(/\s+/, 2);
  if (scheme?.toLowerCase() !== 'bearer' || token !== expectedToken) {
    throw new HttpError(401, 'Invalid inbound bearer token');
  }
}

function ensureMappedClaims(claims: unknown, strategyName: string): Record<string, unknown> {
  if (!isPlainObject(claims)) {
    throw new HttpError(500, `Strategy ${strategyName} produced invalid JWT claims`);
  }

  return claims;
}

function resolveErrorMessage(message: string, context: Record<string, unknown>): string {
  if (message.startsWith('$')) {
    const resolved = resolvePath(message, context);
    return typeof resolved === 'string' ? resolved : message;
  }
  return message;
}

function matchErrorMapping(
  mappings: ErrorMappingConfig[],
  context: Record<string, unknown>,
): ErrorMappingConfig | undefined {
  return mappings.find((mapping) => mapping.condition === undefined || evaluateCondition(mapping.condition, context));
}

async function parseUpstreamBody(response: globalThis.Response): Promise<unknown> {
  const contentType = response.headers.get('content-type') ?? '';
  if (contentType.includes('application/json')) {
    return response.json();
  }

  const text = await response.text();
  if (!text) {
    return null;
  }

  try {
    return JSON.parse(text) as unknown;
  } catch {
    return { raw: text };
  }
}

export class TokenWeaverService {
  private readonly jwtService: JwtService;
  private readonly strategiesByName: ReadonlyMap<string, StrategyConfig>;
  private readonly encryptionKeysByStrategy: ReadonlyMap<string, Uint8Array>;
  /**
   * Compiled JWKS verifiers for 'jwt' strategies, keyed by strategy name. Compiled ONCE:
   * compileAuth holds the remote key set cache, so rebuilding it per request would refetch
   * the JWKS on every exchange.
   */
  private readonly jwtVerifiersByStrategy: ReadonlyMap<string, CompiledAuth>;

  constructor(private readonly gatewayConfig: TokenWeaverConfig) {
    this.strategiesByName = new Map(
      gatewayConfig.strategies.map((strategy) => [strategy.name, strategy] as const),
    );

    // Parse encryption secrets once at startup rather than per request.
    this.encryptionKeysByStrategy = new Map(
      gatewayConfig.strategies.flatMap((strategy) => {
        const encryptedClaims = strategy.encrypted_claims;
        if (!encryptedClaims) {
          return [];
        }

        const key = parseEncryptionKey(
          encryptedClaims.secret,
          `strategy ${strategy.name}: encrypted_claims.secret`,
        );
        return [[strategy.name, key] as const];
      }),
    );

    this.jwtVerifiersByStrategy = new Map(
      gatewayConfig.strategies
        .filter((strategy): strategy is JwtStrategyConfig => strategy.type === 'jwt')
        .map(
          (strategy) =>
            [
              strategy.name,
              compileAuth({
                mode: 'jwt-jwks',
                jwksUri: strategy.verify.jwks_uri,
                issuer: strategy.verify.issuer,
                ...(strategy.verify.audience ? { audience: strategy.verify.audience } : {}),
                ...(strategy.verify.requirements ? { requirements: strategy.verify.requirements } : {}),
              }),
            ] as const,
        ),
    );

    // Only load the RSA private key when at least one strategy uses RS256 signing.
    const needsRsa = gatewayConfig.strategies.some((s) => s.jwt.algorithm === 'RS256');
    this.jwtService = new JwtService(config.TOKEN_WEAVER_KID, needsRsa);
  }

  getRegisteredAuthRoutes(): string[] {
    return this.gatewayConfig.strategies.map((strategy) => `/auth/${strategy.name}`);
  }

  getJwks() {
    return this.jwtService.getJwks();
  }

  async authenticate(req: Request): Promise<AuthSuccessPayload> {
    assertObjectBody(req.body);

    const strategy = this.resolveStrategy(req);
    verifyInboundAuth(strategy.inbound_auth, req);

    if (strategy.type === 'direct') {
      return this.handleDirectStrategy(strategy, req);
    }

    if (strategy.type === 'jwt') {
      return this.handleJwtStrategy(strategy, req);
    }

    return this.handleDelegatedStrategy(strategy, req);
  }

  private resolveStrategy(req: Request): StrategyConfig {
    const strategyName = typeof req.params.name === 'string' ? req.params.name : '';
    const strategy = this.strategiesByName.get(strategyName);
    if (!strategy) {
      throw new HttpError(404, `No matching strategy for name: ${strategyName}`);
    }

    return strategy;
  }

  /**
   * Map the strategy's `encrypted_claims` against the same context the public claims were mapped
   * from, encrypt them into one opaque claim, and add it to the payload. A no-op when the
   * strategy declares no encrypted claims.
   */
  private async addEncryptedClaims(
    strategy: StrategyConfig,
    claims: Record<string, unknown>,
    context: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const encryptedClaims = strategy.encrypted_claims;
    if (!encryptedClaims) {
      return claims;
    }

    const key = this.encryptionKeysByStrategy.get(strategy.name);
    if (!key) {
      throw new HttpError(500, `Strategy ${strategy.name} has no encrypted claims key loaded`);
    }

    const mapped = ensureMappedClaims(mapValue(encryptedClaims.claims, context), strategy.name);

    let blob: string;
    try {
      blob = await encryptClaims(mapped, {
        key,
        ...(encryptedClaims.kid ? { kid: encryptedClaims.kid } : {}),
      });
    } catch (error) {
      // Never surface the error detail — it is derived from the claim values being protected.
      logger.error('Failed to encrypt claims', {
        strategy: strategy.name,
        error: error instanceof Error ? error.message : 'unknown error',
      });
      throw new HttpError(500, 'Failed to encrypt claims');
    }

    return { ...claims, [encryptedClaims.claim]: blob };
  }

  private async issueToken(
    strategy: StrategyConfig,
    claims: Record<string, unknown>,
    context: Record<string, unknown>,
  ): Promise<AuthSuccessPayload> {
    const payload = await this.addEncryptedClaims(strategy, claims, context);

    return {
      token: this.jwtService.sign(payload, strategy.jwt),
      expires_in: strategy.jwt.ttl,
    };
  }

  private async handleDirectStrategy(
    strategy: Extract<StrategyConfig, { type: 'direct' }>,
    req: Request,
  ): Promise<AuthSuccessPayload> {
    const requestContext = buildRequestContext(req) as Record<string, unknown>;
    const credential = resolvePath(
      strategy.credential_path ?? '$.request.body.secret',
      requestContext,
    );
    if (typeof credential !== 'string' || credential.length === 0) {
      throw new HttpError(401, 'Missing credential in request');
    }

    const matchedCredential = strategy.credentials.find(
      (entry: DirectCredential) => entry.secret === credential,
    );
    if (!matchedCredential) {
      throw new HttpError(401, 'Invalid credential');
    }

    const mappedClaims = ensureMappedClaims(mapValue(matchedCredential.claims, requestContext), strategy.name);

    return this.issueToken(strategy, mappedClaims, requestContext);
  }

  /**
   * Exchange an upstream JWT for ours: verify signature/issuer/audience (and any required
   * claims) against the configured JWKS, then mint our token from the mapped claims.
   *
   * Failures surface as the auth core's own status codes - 401 for an unverifiable token, 403
   * when it verifies but does not meet `requirements` - so a caller can tell "your token is
   * bad" from "your token is fine but not allowed to do this".
   */
  private async handleJwtStrategy(
    strategy: JwtStrategyConfig,
    req: Request,
  ): Promise<AuthSuccessPayload> {
    const requestContext = buildRequestContext(req) as Record<string, unknown>;
    const rawCredential = resolvePath(strategy.credential_path, requestContext);
    if (typeof rawCredential !== 'string' || rawCredential.length === 0) {
      throw new HttpError(401, 'Missing token in request');
    }

    const verifier = this.jwtVerifiersByStrategy.get(strategy.name);
    if (!verifier) {
      // Unreachable: verifiers are built for every jwt strategy at construction.
      throw new HttpError(500, `No compiled verifier for strategy: ${strategy.name}`);
    }

    let payload: Record<string, unknown>;
    try {
      // extractBearerToken tolerates a bare token as well as 'Bearer <token>', so
      // credential_path can point at the Authorization header or at a bare field.
      payload = (await verifier({ authorizationHeader: `Bearer ${extractBearerToken(rawCredential)}` })) as Record<
        string,
        unknown
      >;
    } catch (error) {
      const status = (error as { status?: number }).status ?? 401;
      throw new HttpError(status, (error as Error).message || 'Token verification failed');
    }

    // Re-derive the context WITH the verified claims, so mappings can read $.request.jwt.*
    const mappingContext = buildRequestContext(req, payload) as Record<string, unknown>;
    const claims = mapValue(strategy.claims, mappingContext) as Record<string, unknown>;

    return this.issueToken(strategy, claims, mappingContext);
  }

  private async handleDelegatedStrategy(
    strategy: DelegatedStrategyConfig,
    req: Request,
  ): Promise<AuthSuccessPayload> {
    const requestContext = buildRequestContext(req) as Record<string, unknown>;
    const headers = new Headers(strategy.upstream.headers);

    if (strategy.upstream.header_mapping) {
      for (const [key, value] of Object.entries(strategy.upstream.header_mapping)) {
        const mappedValue = mapValue(value, requestContext);
        const headerValue = toComparableString(mappedValue);
        if (headerValue !== undefined) {
          headers.set(key, headerValue);
        }
      }
    }

    if (strategy.upstream.auth?.type === 'bearer' && strategy.upstream.auth.token) {
      headers.set('Authorization', `Bearer ${strategy.upstream.auth.token}`);
    }

    if (strategy.upstream.auth?.type === 'api_key' && strategy.upstream.auth.key) {
      headers.set(strategy.upstream.auth.header ?? 'X-API-Key', strategy.upstream.auth.key);
    }

    let body: string | undefined;
    if (strategy.upstream.body_mapping) {
      headers.set('Content-Type', 'application/json');
      body = JSON.stringify(mapValue(strategy.upstream.body_mapping, requestContext));
    }

    let response: globalThis.Response;
    try {
      response = await httpRequest(
        strategy.upstream.url,
        {
          method: strategy.upstream.method,
          headers,
          body: body ?? null,
          timeoutMs: strategy.upstream.timeout_ms ?? 5000,
          ...(strategy.log?.request_body ? { logRequestBody: true } : {}),
          ...(strategy.log?.response_body ? { logResponseBody: true } : {}),
          ...(strategy.log?.request_headers ? { logRequestHeaders: true } : {}),
        },
        { strategy: strategy.name },
      );
    } catch (error) {
      const isTimeout = error instanceof Error && error.name === 'AbortError';
      throw new UpstreamUnavailableError(
        isTimeout ? 'Upstream service timed out' : 'Upstream service unreachable',
      );
    }

    const responseBody = await parseUpstreamBody(response);

    const evaluationContext: UpstreamContext = isPlainObject(responseBody)
      ? {
          ...responseBody,
          response: {
            status: response.status,
            body: responseBody,
          },
        }
      : {
          value: responseBody,
          response: {
            status: response.status,
            body: responseBody,
          },
        };

    if (!evaluateCondition(strategy.response_mapping.success_condition, evaluationContext)) {
      const errorMappings = strategy.response_mapping.error_mappings ?? [];
      const matched = matchErrorMapping(errorMappings, evaluationContext);

      if (matched) {
        const message = resolveErrorMessage(matched.message, evaluationContext);
        logger.warn('Upstream auth rejected — error mapping matched', {
          strategy: strategy.name,
          upstreamStatus: response.status,
          mappedStatus: matched.status,
          condition: matched.condition,
        });
        throw new HttpError(matched.status, message, matched.code ? { code: matched.code } : undefined);
      }

      logger.warn('Upstream auth rejected', {
        strategy: strategy.name,
        upstreamStatus: response.status,
        successCondition: strategy.response_mapping.success_condition,
      });
      throw new HttpError(401, 'Upstream authentication rejected');
    }

    const mappedClaims = ensureMappedClaims(
      mapValue(strategy.response_mapping.claims, evaluationContext),
      strategy.name,
    );

    return this.issueToken(strategy, mappedClaims, evaluationContext);
  }
}
