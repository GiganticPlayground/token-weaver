/**
 * OpenAPI API Key Authentication Module
 *
 * This module provides API key authentication for express-openapi-validator.
 * It validates API keys from the X-API-Key header against a configuration file.
 */

import { readFileSync } from 'fs';
import { join } from 'path';

import type { NextFunction, Request, Response } from 'express';

// ============================================================================
// Type Definitions
// ============================================================================

/**
 * Configuration structure for a single API key
 */
export interface ApiKeyConfig {
  name: string;
  description: string;
  createdAt: string;
  active: boolean;
}

/**
 * Root configuration structure containing all API keys
 */
export interface ApiKeysConfig {
  apiKeys: { [key: string]: ApiKeyConfig };
}

// ============================================================================
// API Key Manager
// ============================================================================

/**
 * Manages API key validation and configuration loading
 *
 * Usage:
 * ```typescript
 * const manager = new ApiKeyManager();
 * const isValid = manager.validateApiKey('your-api-key');
 * ```
 */
export class ApiKeyManager {
  private config!: ApiKeysConfig;
  private configPath: string;

  /**
   * Creates a new ApiKeyManager instance
   * @param configPath - Optional custom path to api-keys.json (defaults to config/api-keys.json)
   */
  constructor(configPath?: string) {
    this.configPath = configPath ?? join(process.cwd(), 'config/api-keys.json');
    this.loadConfig();
  }

  /**
   * Loads API keys configuration from JSON file
   * @throws Error if configuration file cannot be loaded
   */
  private loadConfig(): void {
    try {
      const configContent = readFileSync(this.configPath, 'utf8');
      this.config = JSON.parse(configContent) as ApiKeysConfig;
    } catch (error) {
      console.error('Failed to load API keys configuration:', error);
      throw new Error('API keys configuration not found');
    }
  }

  /**
   * Validates an API key
   * @param apiKey - The API key to validate
   * @returns true if the key exists and is active, false otherwise
   */
  public validateApiKey(apiKey: string): boolean {
    const keyConfig = this.config.apiKeys[apiKey];
    return !!keyConfig?.active;
  }

  /**
   * Reloads the configuration from disk
   * Useful for hot-reloading API keys without restarting the server
   */
  public reloadConfig(): void {
    this.loadConfig();
  }

  /**
   * Gets information about a specific API key (without exposing sensitive data)
   * @param apiKey - The API key to look up
   * @returns API key configuration or null if not found
   */
  public getKeyInfo(apiKey: string): ApiKeyConfig | null {
    return this.config.apiKeys[apiKey] ?? null;
  }
}

// ============================================================================
// Security Handler Factory
// ============================================================================

/**
 * Creates a security handler function for express-openapi-validator
 *
 * @param apiKeyManager - Instance of ApiKeyManager to use for validation
 * @returns Security handler function compatible with express-openapi-validator
 *
 * Usage with express-openapi-validator:
 * ```typescript
 * import * as OpenApiValidator from "express-openapi-validator";
 * import { createApiKeySecurityHandler, ApiKeyManager } from "./openapi-auth";
 *
 * const apiKeyManager = new ApiKeyManager();
 *
 * app.use(
 *   OpenApiValidator.middleware({
 *     apiSpec: apiSpec,
 *     validateSecurity: {
 *       handlers: {
 *         ApiKeyAuth: createApiKeySecurityHandler(apiKeyManager)
 *       }
 *     }
 *   })
 * );
 * ```
 */
interface AuthError extends Error {
  status: number;
  message: string;
}

export function createApiKeySecurityHandler(apiKeyManager: ApiKeyManager) {
  return (req: Request, _scopes: string[], _schema: unknown): boolean => {
    const apiKey = req.headers['x-api-key'] as string;

    if (!apiKey) {
      const error = new Error('API key is required') as AuthError;
      error.status = 401;
      throw error;
    }

    const isValid = apiKeyManager.validateApiKey(apiKey);
    if (!isValid) {
      const error = new Error('Invalid or inactive API key') as AuthError;
      error.status = 401;
      throw error;
    }

    // Authentication successful
    return true;
  };
}

// ============================================================================
// Express Middleware (Optional)
// ============================================================================

/**
 * Extended request interface with API key info
 */
interface RequestWithApiKey extends Request {
  apiKeyInfo?: ApiKeyConfig;
}

/**
 * Creates an Express middleware for manual API key validation
 * Use this if you want to validate API keys outside of OpenAPI validator
 *
 * @param apiKeyManager - Instance of ApiKeyManager
 * @returns Express middleware function
 *
 * Usage:
 * ```typescript
 * import { createApiKeyMiddleware, ApiKeyManager } from "./openapi-auth";
 *
 * const apiKeyManager = new ApiKeyManager();
 * app.use("/protected", createApiKeyMiddleware(apiKeyManager));
 * ```
 */
export function createApiKeyMiddleware(apiKeyManager: ApiKeyManager) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const apiKey = req.headers['x-api-key'] as string;

    if (!apiKey) {
      res.status(401).json({
        message: 'API key is required',
        code: 'AUTHENTICATION_FAILED',
      });
      return;
    }

    const isValid = apiKeyManager.validateApiKey(apiKey);
    if (!isValid) {
      res.status(401).json({
        message: 'Invalid or inactive API key',
        code: 'AUTHENTICATION_FAILED',
      });
      return;
    }

    // Optionally attach key info to request
    const keyInfo = apiKeyManager.getKeyInfo(apiKey);
    if (keyInfo) {
      (req as RequestWithApiKey).apiKeyInfo = keyInfo;
    }

    next();
  };
}
