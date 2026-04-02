import { z } from 'zod';

/**
 * Environment variables validation schema.
 *
 * - Optional variables will use their default values if not provided
 * - Required variables will cause the application to fail on startup if missing
 */
export const envSchema = z.object({
  /**
   * Server port number
   * @default 3000
   */
  PORT: z
    .string()
    .transform((val) => parseInt(val, 10))
    .pipe(z.number().min(1).max(65535))
    .optional()
    .default(3000),

  /**
   * Application environment
   * Controls logging behavior and other environment-specific features
   * @default development
   */
  NODE_ENV: z.enum(['development', 'production', 'test']).optional().default('development'),

  /**
   * Path to API keys configuration file
   * @default config/api-keys.json
   */
  API_KEYS_CONFIG_PATH: z.string().optional(),
});

/**
 * Inferred TypeScript type from the environment schema
 */
export type Env = z.infer<typeof envSchema>;
