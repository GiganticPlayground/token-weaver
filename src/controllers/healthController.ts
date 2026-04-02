/**
 * healthController
 * Auto-generated from OpenAPI specification
 */

import type { NextFunction } from 'express';

import type { ApiRequest, ApiResponse } from '../types/api-helpers';

/**
 * Health check endpoint
 *
 * @route GET /health
 */
export const getHealth = async (
  req: ApiRequest<'getHealth'>,
  res: ApiResponse<'getHealth'>,
  next: NextFunction,
): Promise<void> => {
  try {
    // TODO: Implement business logic
    // Type information:
    // - req.params: Typed path parameters
    // - req.query: Typed query parameters
    // - req.body: Typed request body

    // TODO: Return properly typed response matching the schema
    res.send({
      status: 'ok',
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
};
