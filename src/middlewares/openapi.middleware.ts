import { join } from 'path';

import * as OpenApiValidator from 'express-openapi-validator';

import { ApiKeyManager, createApiKeySecurityHandler } from '../auth';
import { config } from '../config';

// Initialize API Key Manager
let apiKeyManager: ApiKeyManager | null = null;

try {
  const apiKeysPath = config.API_KEYS_CONFIG_PATH ?? join(process.cwd(), 'config/api-keys.json');
  apiKeyManager = new ApiKeyManager(apiKeysPath);
  // eslint-disable-next-line no-console
  console.log('✓ API Key authentication enabled');
} catch (_error) {
  console.error('⚠ Warning: API key authentication not configured');
  console.error('  To enable authentication:');
  console.error('    1. Copy src/auth/api-keys.json.example to config/api-keys.json');
  console.error('    2. Or run: ./scripts/devsetup.sh');
  console.error('  Endpoints with security requirements will return 401 errors\n');
}

export const createOpenApiValidatorMiddleware = (apiSpec: unknown) =>
  OpenApiValidator.middleware({
    apiSpec: apiSpec as string,
    validateApiSpec: true,
    validateRequests: true, // (default)
    validateResponses: true, // false by default
    operationHandlers: join(process.cwd(), 'src/controllers'),
    validateSecurity: {
      handlers: {
        ApiKeyAuth: apiKeyManager
          ? createApiKeySecurityHandler(apiKeyManager)
          : () => {
              const error = new Error(
                'API key authentication is not configured. Please set up config/api-keys.json',
              ) as Error & { status: number };
              error.status = 401;
              throw error;
            },
      },
    },
  });
