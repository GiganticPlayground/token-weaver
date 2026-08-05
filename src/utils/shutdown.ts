import type { Server } from 'http';

import type { AnalyticsHandle } from 'reqcast';

import { logger } from './logger';

export function setupShutdown(
  server: Server,
  timeoutMs: number,
  analytics: AnalyticsHandle | null = null,
): void {
  let shuttingDown = false;

  const shutdown = async (signal: string) => {
    if (shuttingDown) {
      logger.warn('Shutdown already in progress — ignoring signal', { signal });
      return;
    }
    shuttingDown = true;

    logger.info('Shutdown initiated', { signal, timeoutMs });

    const forceExit = setTimeout(() => {
      logger.warn('Shutdown timeout exceeded — forcing exit', { timeoutMs });
      process.exit(1);
    }, timeoutMs).unref();

    logger.info('Closing HTTP server — stopping new connections');
    await new Promise<void>((resolve) => server.close(() => resolve()));
    logger.info('HTTP server closed');

    // In-flight requests are drained, so their analytics records have been
    // dispatched — flush/close the sinks (e.g. drain file stream, close AMQP).
    if (analytics) {
      await analytics.close();
      logger.info('Analytics sinks closed');
    }

    clearTimeout(forceExit);
    logger.info('Shutdown complete');
    process.exit(0);
  };

  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));
}
