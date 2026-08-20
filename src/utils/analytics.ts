import { existsSync } from 'node:fs';

import { createAnalytics, loadConfig, type AnalyticsHandle } from 'reqcast';

import { logger } from './logger';
import { config } from '../config/index';

/**
 * Default config filenames for the zero-config path, in the order reqcast itself tries them.
 * JSON stays first so a deployment that has both keeps its existing behavior.
 */
const DEFAULT_REQCAST_CONFIGS = [
  './reqcast.config.json',
  './reqcast.config.yaml',
  './reqcast.config.yml',
] as const;

/**
 * Loads the reqcast config from REQCAST_CONFIG, or the first default file that exists. Returns
 * null when neither is present, leaving analytics disabled.
 *
 * YAML and JSON are both accepted (reqcast picks by extension), so the YAML names are checked
 * here too - otherwise a YAML-only deployment would silently get no analytics unless it also set
 * REQCAST_CONFIG.
 */
export function buildAnalytics(): AnalyticsHandle | null {
  const path = config.REQCAST_CONFIG ?? DEFAULT_REQCAST_CONFIGS.find((candidate) => existsSync(candidate));
  if (!path) {
    return null;
  }
  const reqcastConfig = loadConfig(path);
  return createAnalytics(reqcastConfig, {
    logger,
    onError: (err, sinkName) => logger.error('analytics sink error', { sinkName, err }),
  });
}
