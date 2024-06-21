import fs from 'fs';
import path from 'path';
import { beautify } from '../../utils/utility.js';
import { constants } from '../../constant/application.const.js';
import firebaseAdmin from 'firebase-admin';
import logger, { level } from '../../../config/logger.js';

const __dirname = path.resolve();
const filepath = path.join(__dirname, 'src', 'shared', 'services', 'firebase', `${constants.FIREBASE_KEY}.json`);
const serviceAccount = JSON.parse(fs.readFileSync(filepath, 'utf8'));

firebaseAdmin.initializeApp({
  credential: firebaseAdmin.credential.cert(serviceAccount)
});

export const sendPushNotification = async (tokens, message, priority) => {
  logger.log(level.info, `sendPushNotification Token=${beautify(tokens)} \n Message=${message} \n Priority=${priority}`);
  const options = {
    priority,
    timeToLive: 60 * 60 * 24
  }

  return firebaseAdmin.messaging().sendToDevice(tokens, message, options).then(res => {
    logger.log(level.info, `sendPushNotification Res=${beautify(res.results)}`);
    return res;
  }).catch(err => {
    logger.log(level.error, `sendPushNotification Error: ${beautify(err.message)}`);
    return false;
  })
}