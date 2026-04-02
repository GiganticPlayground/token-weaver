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
  TOKEN_WEAVER_CONFIG_PATH: z.string().optional().default('config/token-weaver.yaml'),
  TOKEN_WEAVER_PRIVATE_KEY_PATH: z.string().optional(),
  TOKEN_WEAVER_PRIVATE_KEY: z.string().optional(),
  TOKEN_WEAVER_KID: z.string().optional().default('token-weaver-key'),
});

/**
 * Inferred TypeScript type from the environment schema
 */
export type Env = z.infer<typeof envSchema>;
