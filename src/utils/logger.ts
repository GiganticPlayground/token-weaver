/* eslint-disable no-console */
import { config } from '../config/index';

/**
 * Approved logging utility that respects NODE_ENV settings.
 *
 * In production, only warn() and error() will output logs.
 * In development and test, all logging methods will work.
 *
 * This provides a safe alternative to console.log that won't leak
 * debug information in production environments.
 *
 * Note: ESLint no-console rule is disabled for this file as it is
 * the approved centralized location for all console usage.
 */
class Logger {
  /**
   * Check if we're in a non-production environment
   */
  private isNonProduction(): boolean {
    return config.NODE_ENV !== 'production';
  }

  /**
   * Log general information (suppressed in production)
   */
  log(...args: unknown[]): void {
    if (this.isNonProduction()) {
      console.log('[LOG]', ...args);
    }
  }

  /**
   * Log debug information (suppressed in production)
   */
  debug(...args: unknown[]): void {
    if (this.isNonProduction()) {
      console.log('[DEBUG]', ...args);
    }
  }

  /**
   * Log informational messages (suppressed in production)
   */
  info(...args: unknown[]): void {
    if (this.isNonProduction()) {
      console.log('[INFO]', ...args);
    }
  }

  /**
   * Log warning messages (always logged, including production)
   */
  warn(...args: unknown[]): void {
    console.warn('[WARN]', ...args);
  }

  /**
   * Log error messages (always logged, including production)
   */
  error(...args: unknown[]): void {
    console.error('[ERROR]', ...args);
  }
}

/**
 * Singleton logger instance
 * Usage: import { logger } from './utils'
 */
export const logger = new Logger();
