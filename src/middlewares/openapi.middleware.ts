import { join } from 'path';

import * as OpenApiValidator from 'express-openapi-validator';

export const createOpenApiValidatorMiddleware = (apiSpec: unknown) =>
  OpenApiValidator.middleware({
    apiSpec: apiSpec as string,
    validateApiSpec: true,
    validateRequests: true, // (default)
    validateResponses: false, // false by default
    operationHandlers: join(process.cwd(), 'src/controllers'),
  });
