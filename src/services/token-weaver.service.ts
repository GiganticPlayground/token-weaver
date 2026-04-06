import type { Request } from 'express';

import { JwtService } from './jwt.service';
import { config } from '../config/index';
import type {
  DelegatedStrategyConfig,
  DirectCredential,
  InboundAuthConfig,
  StrategyConfig,
  TokenWeaverConfig,
} from '../config/token-weaver.config';
import { HttpError, UpstreamUnavailableError } from '../utils/http-error';
import { evaluateCondition, resolvePath } from '../utils/path-expression';

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

function buildRequestContext(req: Request): RequestContext {
  return {
    request: {
      body: req.body,
      headers: normalizeHeaders(req.headers),
      query: req.query as Record<string, unknown>,
      params: req.params as Record<string, unknown>,
      path: req.path,
      method: req.method,
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
  private readonly jwtService = new JwtService(config.TOKEN_WEAVER_KID);
  private readonly strategiesByName: ReadonlyMap<string, StrategyConfig>;

  constructor(private readonly gatewayConfig: TokenWeaverConfig) {
    this.strategiesByName = new Map(
      gatewayConfig.strategies.map((strategy) => [strategy.name, strategy] as const),
    );
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

  private issueToken(
    strategy: StrategyConfig,
    claims: Record<string, unknown>,
  ): AuthSuccessPayload {
    return {
      token: this.jwtService.sign(claims, strategy.jwt.ttl, strategy.jwt.issuer),
      expires_in: strategy.jwt.ttl,
    };
  }

  private handleDirectStrategy(
    strategy: Extract<StrategyConfig, { type: 'direct' }>,
    req: Request,
  ): AuthSuccessPayload {
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

    return this.issueToken(strategy, mappedClaims);
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

    const controller = new AbortController();
    const timeout = globalThis.setTimeout(
      () => controller.abort(),
      strategy.upstream.timeout_ms ?? 5000,
    );

    let response: globalThis.Response;
    try {
      response = await globalThis.fetch(strategy.upstream.url, {
        method: strategy.upstream.method,
        headers,
        body: body ?? null,
        signal: controller.signal,
      });
    } catch (error) {
      throw new UpstreamUnavailableError(
        error instanceof Error && error.name === 'AbortError'
          ? 'Upstream service timed out'
          : 'Upstream service unreachable',
      );
    } finally {
      globalThis.clearTimeout(timeout);
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
      throw new HttpError(401, 'Upstream authentication rejected');
    }

    const mappedClaims = ensureMappedClaims(
      mapValue(strategy.response_mapping.claims, evaluationContext),
      strategy.name,
    );

    return this.issueToken(strategy, mappedClaims);
  }
}
