import { decrypt } from '../utils/utility.js';
import 'dotenv/config'

export const constants = {
  MONGO_URL: process.env.MONGO_URL,
  OPEN_EVENT: 'open',
  ERROR_EVENT: 'error',
  DISCONNECTED_EVENT: 'disconnected',
  RECONNECT_FAILED_EVENT: 'reconnectFailed',

  //admin_users
  ADMIN_USER_ACTIVE: 1,
  ADMIN_USER_IN_ACTIVE: 0,

  //trigger type 
  TYPE_KEYWORDS: 0,
  TYPE_ALL_COMMENTS: 1,
  TYPE_EMOJIS_ONLY: 2,
  TYPE_MENTIONS_ONLY: 3,
};