export type Primitive = string | number | boolean | null;
export type MappingValue = Primitive | string[] | number[] | boolean[] | MappingObject;

export interface MappingObject {
  [key: string]: MappingValue;
}

export interface RouteRule {
  path?: string | undefined;
  headers?: Record<string, string> | undefined;
  query?: Record<string, string> | undefined;
}

export interface SharedJwtConfig {
  issuer: string;
  ttl: number;
}

export interface InboundAuthConfig {
  type: 'bearer' | 'api_key' | 'none';
  header?: string | undefined;
  key?: string | undefined;
  token?: string | undefined;
}

export interface DirectCredential {
  secret: string;
  claims: MappingObject;
}

export interface DirectStrategyConfig {
  name: string;
  type: 'direct';
  route?: RouteRule | undefined;
  inbound_auth?: InboundAuthConfig | undefined;
  credential_path?: string | undefined;
  credentials: DirectCredential[];
  jwt: SharedJwtConfig;
}

export interface UpstreamAuthConfig {
  type: 'bearer' | 'api_key' | 'none';
  token?: string | undefined;
  key?: string | undefined;
  header?: string | undefined;
}

export interface UpstreamConfig {
  url: string;
  method: string;
  timeout_ms?: number | undefined;
  auth?: UpstreamAuthConfig | undefined;
  headers?: Record<string, string> | undefined;
  header_mapping?: Record<string, string> | undefined;
  body_mapping?: MappingObject | undefined;
}

export interface ResponseMappingConfig {
  success_condition: string;
  claims: MappingObject;
}

export interface DelegatedStrategyConfig {
  name: string;
  type: 'delegated';
  route?: RouteRule | undefined;
  inbound_auth?: InboundAuthConfig | undefined;
  upstream: UpstreamConfig;
  response_mapping: ResponseMappingConfig;
  jwt: SharedJwtConfig;
}

export type StrategyConfig = DirectStrategyConfig | DelegatedStrategyConfig;

export interface TokenWeaverConfig {
  strategies: StrategyConfig[];
}

export interface AuthSuccessPayload {
  token: string;
  expires_in: number;
}

export interface JwksResponse {
  keys: Array<JsonWebKey & { use: string; alg: string; kid: string }>;
}
