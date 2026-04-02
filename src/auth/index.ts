/**
 * Authentication Module Barrel Export
 *
 * Exports API key authentication components for use throughout the application
 */

export {
  ApiKeyManager,
  createApiKeySecurityHandler,
  createApiKeyMiddleware,
  type ApiKeyConfig,
  type ApiKeysConfig,
} from './openapi-auth';
