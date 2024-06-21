import mongoose from 'mongoose';
import { logger, level } from './logger.js';
import { constants as DB_CONST } from '../shared/constant/database.const.js';

const URL = DB_CONST.MONGO_URL;

(async () => {
  try {
    await mongoose.connect(URL, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
  } catch (e) {
    logger.log(level.error, `database connection error ${e}`);
  }
})();
// mongoose.set('debug', true);

const connection = mongoose.connection;

connection.once(DB_CONST.OPEN_EVENT, () => {
  logger.log(level.info, `Successfully connected to database at ${URL}`);
});

connection.on(DB_CONST.DISCONNECTED_EVENT, () => {
  logger.log(level.error, `disconnected event to database at ${URL}`);
});

connection.on(DB_CONST.RECONNECT_FAILED_EVENT, () => {
  logger.log(level.error, `reconnectFailed event to database at ${URL}`);
});

connection.on(DB_CONST.ERROR_EVENT, () => {
  logger.log(
    level.error,
    `database connection error while connecting at ${URL}`
  );
});