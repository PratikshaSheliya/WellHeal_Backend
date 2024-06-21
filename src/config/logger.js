import { get } from 'express-http-context';
import winstonLogger from './winston.js';

const formatMessage = function (message) {
  var email = get('email');
  message = email ? message + ' email: ' + email : message;
  return message;
};

const ERROR = 'error';
const WARN = 'warn';
const INFO = 'info';
const VERBOSE = 'verbose';
const DEBUG = 'debug';
const SILLY = 'silly';

export const logger = {
  log: (log_level, message) => {
    switch (log_level) {
      case log_level:
        winstonLogger.log({
          level: log_level,
          message: formatMessage(message)
        });
        break;
      default:
        winstonLogger.log({
          level: INFO,
          message: formatMessage(message)
        });
        break;
    }
  }
};

export const level = {
  error: ERROR,
  warn: WARN,
  info: INFO,
  verbose: VERBOSE,
  debug: DEBUG,
  silly: SILLY
};
export default logger;