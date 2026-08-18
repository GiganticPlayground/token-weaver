import { readFileSync } from 'fs';
import { join } from 'path';

import cors from 'cors';
import express from 'express';
import helmet from 'helmet';
import swaggerUi from 'swagger-ui-express';

import { config } from './config/index';
import {
  authRateLimitMiddleware,
  createOpenApiValidatorMiddleware,
  errorHandlerMiddleware,
  requestContextMiddleware,
} from './middlewares/index';
import { buildAnalytics, logger } from './utils/index';
import { setupShutdown } from './utils/shutdown';

// Load OpenAPI specification
export const apiSpecPath: string = join(process.cwd(), 'api/openapi.yaml');
const apiSpecContent: string = readFileSync(apiSpecPath, 'utf8');

const app = express();
app.set('trust proxy', config.TRUST_PROXY);

const corsOptions =
  !config.CORS_ORIGINS || config.CORS_ORIGINS === '*'
    ? undefined
    : {
        origin: config.CORS_ORIGINS,
      };

// Security and body parsing middleware
app.use(helmet());
app.use(cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(requestContextMiddleware);

const analytics = buildAnalytics();
if (analytics?.enabled) {
  app.use(analytics.middleware);
  logger.info('request analytics enabled');
}

if (config.API_DOCS_ENABLED) {
  // Publish the spec at its own addressable URL, and point the UI at that URL rather than
  // embedding the document in swagger-ui-init.js. Embedding leaves the spec readable only by
  // scraping an internal of swagger-ui-express; a plain route lets any consumer - another docs
  // site, a codegen step, a contract test - fetch it directly.
  //
  // Deliberately served OUTSIDE the '/api-docs' prefix: swaggerUi.serve answers every path
  // under that prefix, so a route beneath it would only work if registered first.
  app.get('/api-docs.yaml', (_req, res) => {
    res.type('application/yaml').send(apiSpecContent);
  });

  app.use(
    '/api-docs',
    swaggerUi.serve,
    swaggerUi.setup(null, {
      explorer: true,
      customCss: '.swagger-ui .topbar { display: none }',
      customSiteTitle: 'API Documentation',
      swaggerOptions: {
        // Relative, so the UI still finds the spec when this service is mounted behind a
        // path prefix. Resolves against '/api-docs/' to '/api-docs.yaml'.
        url: '../api-docs.yaml',
      },
    }),
  );
}

if (config.RATE_LIMIT_ENABLED) {
  app.use('/auth', authRateLimitMiddleware);
}
app.use(createOpenApiValidatorMiddleware(apiSpecPath));
app.use(errorHandlerMiddleware);

const server = app.listen(config.PORT, () => {
  logger.info(`Server is running on port ${config.PORT}`);
});

setupShutdown(server, config.SHUTDOWN_TIMEOUT_MS, analytics);
