import { readFileSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

import cors from 'cors';
import express from 'express';
import helmet from 'helmet';
import swaggerUi from 'swagger-ui-express';
import YAML from 'yaml';

import { config } from './config/index';
import { createOpenApiValidatorMiddleware, errorHandlerMiddleware } from './middlewares/index';
import { logger } from './utils/index';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load OpenAPI specification
export const apiSpecPath: string = join(__dirname, '../api/openapi.yaml');
const apiSpecContent: string = readFileSync(apiSpecPath, 'utf8');
const apiSpec: swaggerUi.JsonObject = YAML.parse(apiSpecContent) as swaggerUi.JsonObject;

const app = express();

// Security and body parsing middleware
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  '/api-docs',
  swaggerUi.serve,
  swaggerUi.setup(apiSpec, {
    explorer: true,
    customCss: '.swagger-ui .topbar { display: none }',
    customSiteTitle: 'API Documentation',
  }),
);

app.use(createOpenApiValidatorMiddleware(apiSpecPath));
app.use(errorHandlerMiddleware);

app.listen(config.PORT, () => {
  logger.info(`Server is running on port ${config.PORT}`);
});
