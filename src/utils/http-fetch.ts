import { logger } from './logger';

export interface HttpRequestOptions extends Omit<RequestInit, 'signal'> {
  timeoutMs?: number;
}

export async function httpRequest(
  url: string,
  options: HttpRequestOptions,
  ctx: Record<string, unknown> = {},
): Promise<Response> {
  const { timeoutMs, ...fetchOptions }: { timeoutMs?: number } & RequestInit = options;
  const method = (fetchOptions.method ?? 'GET').toUpperCase();
  const startedAt = Date.now();

  let controller: AbortController | undefined;
  let timeoutId: ReturnType<typeof globalThis.setTimeout> | undefined;

  if (timeoutMs !== undefined) {
    controller = new AbortController();
    timeoutId = globalThis.setTimeout(() => controller!.abort(), timeoutMs);
    fetchOptions.signal = controller.signal;
  }

  logger.info('START - HTTP', { method, url, ...ctx });

  try {
    const response = await globalThis.fetch(url, fetchOptions);
    logger.info('END - HTTP', {
      method,
      url,
      statusCode: response.status,
      durationMs: Date.now() - startedAt,
      ...ctx,
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
