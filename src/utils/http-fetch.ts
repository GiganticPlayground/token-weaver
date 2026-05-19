import { logger } from './logger';

export interface HttpRequestOptions extends Omit<RequestInit, 'signal'> {
  timeoutMs?: number;
  logRequestBody?: boolean;
  logResponseBody?: boolean;
  logRequestHeaders?: boolean;
}

export async function httpRequest(
  url: string,
  options: HttpRequestOptions,
  ctx: Record<string, unknown> = {},
): Promise<Response> {
  const { timeoutMs, logRequestBody, logResponseBody, logRequestHeaders, ...fetchOptions }: HttpRequestOptions & RequestInit = options;
  const method = (fetchOptions.method ?? 'GET').toUpperCase();
  const startedAt = Date.now();

  let controller: AbortController | undefined;
  let timeoutId: ReturnType<typeof globalThis.setTimeout> | undefined;

  if (timeoutMs !== undefined) {
    controller = new AbortController();
    timeoutId = globalThis.setTimeout(() => controller!.abort(), timeoutMs);
    fetchOptions.signal = controller.signal;
  }

  const startExtras: Record<string, unknown> = {};
  if (logRequestHeaders && fetchOptions.headers) {
    startExtras.requestHeaders = Object.fromEntries(new Headers(fetchOptions.headers as ConstructorParameters<typeof Headers>[0]));
  }
  if (logRequestBody && fetchOptions.body != null) {
    try {
      startExtras.requestBody = typeof fetchOptions.body === 'string'
        ? (JSON.parse(fetchOptions.body) as unknown)
        : fetchOptions.body;
    } catch {
      startExtras.requestBody = fetchOptions.body;
    }
  }

  logger.info('START - HTTP', { method, url, ...ctx, ...startExtras });

  try {
    const response = await globalThis.fetch(url, fetchOptions);

    const endExtras: Record<string, unknown> = {};
    if (logResponseBody) {
      try {
        const text = await response.clone().text();
        endExtras.responseBody = text ? (JSON.parse(text) as unknown) : null;
      } catch {
        // ignore body parse errors for logging
      }
    }

    logger.info('END - HTTP', {
      method,
      url,
      statusCode: response.status,
      durationMs: Date.now() - startedAt,
      ...ctx,
      ...endExtras,
    });
    return response;
  } catch (err) {
    logger.info('END - HTTP', {
      method,
      url,
      error: err instanceof Error ? err.message : String(err),
      durationMs: Date.now() - startedAt,
      ...ctx,
    });
    throw err;
  } finally {
    if (timeoutId !== undefined) {
      globalThis.clearTimeout(timeoutId);
    }
  }
}
