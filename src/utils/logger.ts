import { LOG_TYPES, createLogger } from 'logra';

import { config } from '../config/index';

const logLevel = config.NODE_ENV === 'production' ? 'info' : 'debug';
const logStyle = config.NODE_ENV === 'production' ? LOG_TYPES.JSON : LOG_TYPES.PRETTY;

export const logger = createLogger('token-weaver', {
  level: logLevel,
  style: logStyle,
});
