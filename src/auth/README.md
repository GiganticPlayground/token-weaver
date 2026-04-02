# OpenAPI API Key Authentication

This folder contains a portable authentication implementation for Express.js applications using `express-openapi-validator` with API key authentication.

## Overview

This authentication system validates API keys from the `X-API-Key` header against a JSON configuration file. It integrates seamlessly with `express-openapi-validator` to provide automatic authentication for your OpenAPI-defined endpoints.

## Features

- ✅ API key validation from `X-API-Key` header
- ✅ Active/inactive key management
- ✅ Configuration hot-reload support
- ✅ TypeScript support with full type definitions
- ✅ Express middleware for manual validation
- ✅ Zero database dependencies (file-based)

## Files

- `openapi-auth.ts` - Main authentication module
- `api-keys.json.example` - Example API keys configuration
- `README.md` - This documentation file

## Installation

### 1. Copy Files to Your Project

```bash
# Copy the authentication module
cp auth-code/openapi-auth.ts src/auth/openapi-auth.ts

# Copy and configure API keys
mkdir -p config
cp auth-code/api-keys.json.example config/api-keys.json
```

### 2. Install Dependencies

```bash
npm install express-openapi-validator
```

### 3. Configure Your OpenAPI Specification

Add the security scheme to your `openapi.yaml`:

```yaml
components:
  securitySchemes:
    ApiKeyAuth:
      type: apiKey
      in: header
      name: X-API-Key
      description: API key for authentication

# Apply globally to all endpoints
security:
  - ApiKeyAuth: []

paths:
  /protected-endpoint:
    get:
      summary: A protected endpoint
      security:
        - ApiKeyAuth: [] # Requires authentication
      responses:
        '200':
          description: Success
        '401':
          description: Unauthorized

  /public-endpoint:
    get:
      summary: A public endpoint
      security: [] # No authentication required
      responses:
        '200':
          description: Success
```

**Key Points:**

- The security scheme name `ApiKeyAuth` must match the handler name in your code
- Use `security: []` to make specific endpoints public
- The `X-API-Key` header name is defined in the OpenAPI spec

## Usage

### Basic Setup with express-openapi-validator

```typescript
import express from "express";
import * as OpenApiValidator from "express-openapi-validator";
import { ApiKeyManager, createApiKeySecurityHandler } from "./auth/openapi-auth";

const app = express();

// Load your OpenAPI specification
const apiSpec = ...; // Load from YAML or JSON

// Create API key manager
const apiKeyManager = new ApiKeyManager();
// Or with custom config path:
// const apiKeyManager = new ApiKeyManager("/custom/path/api-keys.json");

// Setup OpenAPI validator with authentication
app.use(
  OpenApiValidator.middleware({
    apiSpec: apiSpec,
    validateApiSpec: true,
    validateRequests: true,
    validateResponses: false,
    operationHandlers: "./controllers",
    validateSecurity: {
      handlers: {
        // This name must match your OpenAPI security scheme name
        ApiKeyAuth: createApiKeySecurityHandler(apiKeyManager)
      }
    }
  })
);

// Error handling middleware
app.use((err, req, res, next) => {
  if (err.status === 401) {
    return res.status(401).json({
      message: err.message || "Unauthorized",
      code: "AUTHENTICATION_FAILED"
    });
  }

  res.status(err.status || 500).json({
    message: err.message || "Internal server error"
  });
});

app.listen(3000);
```

### Alternative: Manual Middleware Setup

If you need API key validation outside of OpenAPI validator:

```typescript
import { ApiKeyManager, createApiKeyMiddleware } from './auth/openapi-auth';

const apiKeyManager = new ApiKeyManager();
const apiKeyAuth = createApiKeyMiddleware(apiKeyManager);

// Apply to specific routes
app.use('/api/protected', apiKeyAuth);

// Or individual routes
app.get('/secure-endpoint', apiKeyAuth, (req, res) => {
  // Access key info if needed
  console.log(req.apiKeyInfo);
  res.json({ message: 'Authenticated!' });
});
```

## Configuration File Structure

Create `config/api-keys.json`:

```json
{
  "apiKeys": {
    "your-api-key-here": {
      "name": "My API Key",
      "description": "Description of what this key is for",
      "createdAt": "2024-01-01T00:00:00Z",
      "active": true
    },
    "another-key": {
      "name": "Another Key",
      "description": "A different service",
      "createdAt": "2024-01-15T00:00:00Z",
      "active": false
    }
  }
}
```

**Important:** Never commit real API keys to version control! Add to `.gitignore`:

```
config/api-keys.json
```

Commit only the example file:

```
config/api-keys.json.example
```

## API Key Management

### Adding a New API Key

1. Generate a secure random key:

   ```bash
   # Linux/macOS
   openssl rand -hex 32

   # Or use Node.js
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
   ```

2. Add to `config/api-keys.json`:
   ```json
   {
     "apiKeys": {
       "new-key-abc123...": {
         "name": "New Service Key",
         "description": "API key for new service",
         "createdAt": "2024-03-01T00:00:00Z",
         "active": true
       }
     }
   }
   ```

### Deactivating an API Key

Set `active: false` instead of deleting (preserves audit trail):

```json
{
  "apiKeys": {
    "old-key": {
      "name": "Old Key",
      "description": "Deprecated",
      "createdAt": "2023-01-01T00:00:00Z",
      "active": false
    }
  }
}
```

### Hot-Reload Configuration

Reload API keys without restarting the server:

```typescript
// Add an admin endpoint
app.post('/admin/reload-keys', async (req, res) => {
  apiKeyManager.reloadConfig();
  res.json({ message: 'API keys reloaded' });
});
```

## Testing Authentication

### Test with cURL

```bash
# Without API key (should fail)
curl http://localhost:3000/protected-endpoint

# With valid API key (should succeed)
curl -H "X-API-Key: your-api-key-here" http://localhost:3000/protected-endpoint

# With invalid key (should fail)
curl -H "X-API-Key: invalid-key" http://localhost:3000/protected-endpoint
```

### Test with JavaScript/Fetch

```javascript
fetch('http://localhost:3000/protected-endpoint', {
  headers: {
    'X-API-Key': 'your-api-key-here',
    'Content-Type': 'application/json',
  },
})
  .then((res) => res.json())
  .then((data) => console.log(data));
```

## OpenAPI Specification Details

### Security Scheme Definition

The security scheme in your OpenAPI spec must match this structure:

```yaml
components:
  securitySchemes:
    ApiKeyAuth: # This name is referenced in your code
      type: apiKey # Must be "apiKey"
      in: header # API key comes from header
      name: X-API-Key # Header name (can be customized)
      description: API key for authentication
```

### Endpoint-Level Security

```yaml
paths:
  /users:
    get:
      # Requires authentication (inherits from global security)
      summary: Get all users
      responses:
        '200':
          description: Success

  /health:
    get:
      # Public endpoint (overrides global security)
      summary: Health check
      security: [] # Empty array = no auth required
      responses:
        '200':
          description: Success
```

### Error Responses

Always define 401 responses in your OpenAPI spec:

```yaml
paths:
  /protected:
    get:
      security:
        - ApiKeyAuth: []
      responses:
        '200':
          description: Success
        '401':
          description: Unauthorized
          content:
            application/json:
              schema:
                type: object
                properties:
                  message:
                    type: string
                  code:
                    type: string
```

## Common Integration Patterns

### Pattern 1: Global Auth with Public Exceptions

```yaml
# Global security
security:
  - ApiKeyAuth: []

paths:
  /health:
    get:
      security: [] # Public

  /users:
    get:
      # Inherits global security (protected)
```

### Pattern 2: Explicit Per-Endpoint Auth

```yaml
# No global security
paths:
  /public:
    get:
      # No security defined (public)

  /protected:
    get:
      security:
        - ApiKeyAuth: [] # Explicitly protected
```

### Pattern 3: Multiple Auth Schemes

```yaml
components:
  securitySchemes:
    ApiKeyAuth:
      type: apiKey
      in: header
      name: X-API-Key
    BearerAuth:
      type: http
      scheme: bearer

paths:
  /endpoint:
    get:
      security:
        - ApiKeyAuth: [] # Option 1: API Key
        - BearerAuth: [] # Option 2: Bearer token
```

Then in your code:

```typescript
validateSecurity: {
  handlers: {
    ApiKeyAuth: createApiKeySecurityHandler(apiKeyManager),
    BearerAuth: createBearerSecurityHandler() // Your implementation
  }
}
```

## Troubleshooting

### "API keys configuration not found"

**Solution:** Ensure `config/api-keys.json` exists and is readable:

```bash
ls -la config/api-keys.json
```

### "API key is required" on every request

**Possible causes:**

1. Header name mismatch - check OpenAPI spec `name: X-API-Key` matches your client
2. Security scheme name mismatch - `ApiKeyAuth` in spec must match handler name
3. Client not sending header

**Debug:**

```typescript
// Add logging to security handler
ApiKeyAuth: (req, scopes, schema) => {
  console.log('Headers:', req.headers);
  const apiKey = req.headers['x-api-key'];
  console.log('API Key:', apiKey);
  // ... rest of handler
};
```

### "Invalid or inactive API key"

**Solution:** Check `config/api-keys.json`:

1. Key exists in the `apiKeys` object
2. `active: true` is set
3. Key string matches exactly (no extra spaces)

### Public endpoint requires authentication

**Solution:** Add `security: []` to the endpoint in OpenAPI spec:

```yaml
/health:
  get:
    security: [] # Override global security
```

## Security Best Practices

1. **Never commit API keys to version control**

   ```bash
   echo "config/api-keys.json" >> .gitignore
   ```

2. **Use environment-specific keys**
   - Different keys for dev, staging, production
   - Rotate keys regularly

3. **Generate strong keys**

   ```bash
   openssl rand -hex 32  # 256-bit key
   ```

4. **Monitor key usage**
   - Add logging to track which keys are used
   - Implement rate limiting per key

5. **Implement key rotation**
   - Keep old key active during transition
   - Deactivate after migration complete

6. **Use HTTPS in production**
   - API keys in headers are vulnerable over HTTP

## Advanced Usage

### Custom Validation Logic

Extend the security handler for custom validation:

```typescript
export function createApiKeySecurityHandler(apiKeyManager: ApiKeyManager) {
  return (req: Request, scopes: string[], schema: any): boolean => {
    const apiKey = req.headers['x-api-key'] as string;

    if (!apiKey) {
      throw { status: 401, message: 'API key is required' };
    }

    const isValid = apiKeyManager.validateApiKey(apiKey);
    if (!isValid) {
      throw { status: 401, message: 'Invalid or inactive API key' };
    }

    // Custom: Check scopes if needed
    const keyInfo = apiKeyManager.getKeyInfo(apiKey);
    if (scopes.length > 0 && keyInfo) {
      // Implement scope checking logic
      // if (!keyInfo.scopes.includes(scope)) { throw 403 }
    }

    // Custom: Rate limiting, IP whitelisting, etc.

    return true;
  };
}
```

### Rate Limiting by API Key

```typescript
import rateLimit from 'express-rate-limit';

const apiKeyRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each key to 100 requests per windowMs
  keyGenerator: (req) => req.headers['x-api-key'] || 'unknown',
});

app.use('/api', apiKeyRateLimiter);
```

## License

This code is provided as-is for use in your projects. Modify as needed.
