# Adding Environment Variables

This guide walks you through the process of adding a new environment variable to the project with proper validation and type safety.

## Overview

The project uses:
- **Zod** for runtime validation of environment variables
- **TypeScript** for compile-time type safety
- **dotenv** for loading environment variables from `.env` files

All environment variables are validated on application startup, ensuring the app fails fast if configuration is invalid.

## Steps to Add a New Environment Variable

### 1. Define the Variable in the Zod Schema

Open `src/config/env.validation.ts` and add your new variable to the `envSchema` object.

#### Example: Adding a required string variable

```typescript
export const envSchema = z.object({
  // ... existing variables ...

  /**
   * Database connection URL
   */
  DATABASE_URL: z.string().url(),
});
```

#### Example: Adding an optional variable with a default

```typescript
export const envSchema = z.object({
  // ... existing variables ...

  /**
   * API rate limit per minute
   * @default 100
   */
  RATE_LIMIT: z
    .string()
    .transform((val) => parseInt(val, 10))
    .pipe(z.number().min(1).max(10000))
    .optional()
    .default(100),
});
```

#### Example: Adding an enum variable

```typescript
export const envSchema = z.object({
  // ... existing variables ...

  /**
   * Application environment
   * @default development
   */
  NODE_ENV: z
    .enum(['development', 'production', 'test'])
    .optional()
    .default('development'),
});
```

#### Example: Adding a boolean variable

```typescript
export const envSchema = z.object({
  // ... existing variables ...

  /**
   * Enable debug logging
   * @default false
   */
  DEBUG: z
    .string()
    .transform((val) => val === 'true')
    .pipe(z.boolean())
    .optional()
    .default(false),
});
```

### 2. Add Documentation Comment

Always add a JSDoc comment above your variable definition. This serves as inline documentation and helps other developers understand the variable's purpose.

```typescript
/**
 * Brief description of what this variable does
 * @default value_if_optional
 */
VARIABLE_NAME: z.string(),
```

### 3. Update the `.env.example` File

Add your new variable to `.env.example` in the project root with a descriptive comment and example value:

```bash
# Brief description
# Default: default_value (if applicable)
VARIABLE_NAME=example_value
```

**Example:**
```bash
# Database Configuration
# PostgreSQL connection URL
DATABASE_URL=postgresql://user:password@localhost:5432/dbname

# API Configuration
# Rate limit per minute per IP address
# Default: 100
RATE_LIMIT=100
```

### 4. Add to Your Local `.env` File

If the variable is required, add it to your local `.env` file:

```bash
VARIABLE_NAME=actual_value
```

If it's optional with a default, you can omit it from `.env` unless you need a different value.

### 5. Use the Variable in Your Code

The validated environment variables are available through the `config` object:

```typescript
import { config } from './config/index';

// Access your variable
const databaseUrl = config.DATABASE_URL;
const rateLimit = config.RATE_LIMIT;
```

TypeScript will provide autocomplete and type checking for all environment variables.

## Common Validation Patterns

### String Validations

```typescript
// Required string
API_KEY: z.string().min(1),

// String with minimum/maximum length
USERNAME: z.string().min(3).max(20),

// URL validation
API_ENDPOINT: z.string().url(),

// Email validation
ADMIN_EMAIL: z.string().email(),

// Custom regex pattern
PHONE_NUMBER: z.string().regex(/^\+?[1-9]\d{1,14}$/),
```

### Number Validations

```typescript
// Integer within range
PORT: z
  .string()
  .transform((val) => parseInt(val, 10))
  .pipe(z.number().int().min(1).max(65535)),

// Positive number
TIMEOUT: z
  .string()
  .transform((val) => parseFloat(val))
  .pipe(z.number().positive()),
```

### Boolean Validations

```typescript
// Boolean from string
ENABLE_FEATURE: z
  .string()
  .transform((val) => val === 'true')
  .pipe(z.boolean()),
```

### Enum Validations

```typescript
// Predefined set of values
LOG_LEVEL: z.enum(['debug', 'info', 'warn', 'error']),
```

## Best Practices

1. **Always validate** - Don't skip validation even for "simple" variables
2. **Fail fast** - Use required variables when the app can't function without them
3. **Provide defaults** - Use sensible defaults for optional configuration
4. **Document everything** - Add JSDoc comments and update `.env.example`
5. **Use specific types** - Transform strings to appropriate types (number, boolean, etc.)
6. **Add constraints** - Use `.min()`, `.max()`, `.url()`, etc. to catch invalid values early
7. **Never commit `.env`** - The `.env` file should be in `.gitignore` (secrets should never be committed)

## Troubleshooting

### Error: "Environment variable validation failed"

The application will show which variables failed validation and why. Example error:

```
Environment variable validation failed:
  - DATABASE_URL: Invalid url
  - PORT: Number must be greater than 0

Please check your .env file or environment configuration.
```

**Solution:** Check your `.env` file and fix the invalid values according to the error messages.

### Error: "Expected string, received undefined"

A required environment variable is missing.

**Solution:** Add the missing variable to your `.env` file or make it optional with `.optional()` if appropriate.

## Example: Complete Workflow

Let's add a `JWT_SECRET` variable:

**Step 1:** Update `src/config/env.validation.ts`:

```typescript
export const envSchema = z.object({
  PORT: z
    .string()
    .transform((val) => parseInt(val, 10))
    .pipe(z.number().min(1).max(65535))
    .optional()
    .default(3000),

  /**
   * Secret key for JWT token signing
   * Must be at least 32 characters for security
   */
  JWT_SECRET: z.string().min(32),
});
```

**Step 2:** Update `.env.example`:

```bash
# Server Configuration
# Port number for the Express server
# Default: 3000
PORT=3000

# Security Configuration
# Secret key for JWT token signing (minimum 32 characters)
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
```

**Step 3:** Add to `.env`:

```bash
PORT=3000
JWT_SECRET=my-development-secret-key-at-least-32-chars-long
```

**Step 4:** Use in code:

```typescript
import { config } from './config/index';
import jwt from 'jsonwebtoken';

const token = jwt.sign(payload, config.JWT_SECRET);
```

Done! Your environment variable is now validated, type-safe, and ready to use.

## Related Files

- `src/config/env.validation.ts` - Zod schema definition
- `src/config/configuration.ts` - Validation logic
- `src/config/index.ts` - Exported config object
- `.env.example` - Template for environment variables
- `.env` - Your local environment variables (not committed to git)
