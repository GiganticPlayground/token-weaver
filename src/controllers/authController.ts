import type { NextFunction, Request, Response } from 'express';

import { tokenWeaverService } from '../services';

export const postAuth = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const result = await tokenWeaverService.authenticate(req);
    res.status(200).json(result);
  } catch (error) {
    next(error);
  }
};

export const getJwks = async (_req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    res.status(200).json(tokenWeaverService.getJwks());
  } catch (error) {
    next(error);
  }
};
