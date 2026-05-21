import { z } from 'zod';

/**
 * Environment variables validation schema.
 *
 * - Optional variables will use their default values if not provided
 * - Required variables will cause the application to fail on startup if missing
 */
export const envSchema = z.object({
  PORT: z
    .string()
    .transform((val) => parseInt(val, 10))
    .pipe(z.number().min(1).max(65535))
    .optional()
    .default(3000),
  NODE_ENV: z.enum(['development', 'production', 'test']).optional().default('development'),
  LOG_LEVEL: z
    .enum(['silly', 'trace', 'debug', 'info', 'warn', 'error', 'fatal'])
    .optional()
    .default('debug'),
  LOG_TYPE: z.enum(['json', 'pretty', 'hidden']).optional().default('pretty'),
  CORS_ORIGINS: z
    .string()
    .optional()
    .transform((value) => {
      if (!value) {
        return undefined;
      }

      if (value === '*') {
        return '*';
      }

      const origins = value
        .split(',')
        .map((origin) => origin.trim())
        .filter((origin) => origin.length > 0);

      return origins.length > 0 ? origins : undefined;
    }),
  TRUST_PROXY: z
    .string()
    .optional()
    .default('false')
    .transform((value) => {
      if (!value || value === 'false') {
        return false;
      }

      if (value === 'true') {
        return true;
      }

      const parsed = parseInt(value, 10);
      return Number.isNaN(parsed) ? false : parsed;
    }),
  API_DOCS_ENABLED: z
    .enum(['true', 'false'])
    .optional()
    .default('true')
    .transform((value) => value === 'true'),
  RATE_LIMIT_ENABLED: z
    .enum(['true', 'false'])
    .optional()
    .default('false')
    .transform((value) => value === 'true'),
  RATE_LIMIT_MAX: z
    .string()
    .transform((val) => parseInt(val, 10))
    .pipe(z.number().int().positive())
    .optional()
    .default(30),
  RATE_LIMIT_WINDOW_MS: z
    .string()
    .transform((val) => parseInt(val, 10))
    .pipe(z.number().int().positive())
    .optional()
    .default(60_000),
  TOKEN_WEAVER_CONFIG_PATH: z.string().optional().default('config/token-weaver.yaml'),
  TOKEN_WEAVER_PRIVATE_KEY_PATH: z.string().optional(),
  TOKEN_WEAVER_PRIVATE_KEY: z.string().optional(),
  TOKEN_WEAVER_KID: z.string().optional().default('token-weaver-key'),
  SHUTDOWN_TIMEOUT_MS: z
    .string()
    .transform((val) => parseInt(val, 10))
    .pipe(z.number().int().positive())
    .optional()
    .default(30_000),
});

/**
 * Inferred TypeScript type from the environment schema
 */
export type Env = z.infer<typeof envSchema>;
