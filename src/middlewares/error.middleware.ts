import { NextFunction, Request, Response } from 'express';

interface CustomError extends Error {
  status?: number;
  errors?: unknown;
}

interface ExpressHandler<T extends Error> {
  (err: T, req: Request, res: Response, next: NextFunction): void;
}

export const errorHandlerMiddleware: ExpressHandler<CustomError> = (err, _req, res, _next) => {
  // format error
  console.error('OpenAPI Validator Error:', err);

  // Handle validation errors
  if (err.status === 400 && err.errors) {
    return res.status(400).json({
      message: 'Validation error',
      errors: err.errors,
    });
  }

  // Handle authentication/authorization errors
  if (err.status === 401) {
    return res.status(401).json({
      message: err.message || 'Unauthorized',
      code: 'AUTHENTICATION_FAILED',
    });
  }

  if (err.status === 403) {
    return res.status(403).json({
      message: err.message || 'Forbidden',
      code: 'AUTHORIZATION_FAILED',
    });
  }

  // Handle other errors
  return res.status(err.status ?? 500).json({
    message: err.message || 'Internal server error',
    ...(err.errors ? { errors: err.errors } : {}),
  });
};
