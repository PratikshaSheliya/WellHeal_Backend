import express from 'express';
import cron from 'node-cron';
import './config/database.js';
import './shared/utils/utility.js';
import middlewaresConfig from './config/middlewares.js';
import ApiRoutes from './routes/index.js';
import path from 'path';
import { constants } from './shared/constant/application.const.js';
import logger, { level } from './config/logger.js';
import { scheduleNotificationByCron } from './cron/schedule_notification.js';
import { autoEndFreeTrial } from './cron/autoEndFreeTrial.js';
import { subscriptionFreeTrialEnd } from './cron/subscriptionFreeTrialEnd.js';
import { subscriptionPlanCancelByUserPlanAutoEnd ,subscriptionAutoEndNonCancel } from './cron/subscriptionAutoEnd.js';
// import './cron/generic_reminders.js';

// cron.schedule(
//   '*/15 * * * * *',
//   async () => {
//     subscriptionFreeTrialEnd();
//     subscriptionPlanCancelByUserPlanAutoEnd();
//     subscriptionAutoEndNonCancel();
//   },
//   { scheduled: true }
// );

// cron.schedule(
//   '* * * * *',
//   async () => {
//     //autoEndFreeTrial();
//     scheduleNotificationByCron();
//   },
//   { scheduled: true }
// );

// // Run the cron job at midnight (12:00 AM)
// cron.schedule(
//   '0 0 * * *',
//   async () => {
//     autoEndFreeTrial();
//   },
//   { scheduled: true }
// );

const __dirname = path.resolve();
const app = express();
middlewaresConfig(app);

app.set('views', path.join(__dirname, 'src', 'views'));
app.set('view engine', 'ejs');
app.use(express.static('src/public'));

app.use('/api', ApiRoutes);

app.listen(constants.PORT, () => {
  logger.log(level.info, `SERVER RUNNING ON PORT ${constants.PORT}`);
});

export default app;
