import cron from 'node-cron'

import User from '../models/user.model.js';

cron.schedule('* * */7 * * *', async () => {
  const users = await User.get({ status: 1 });
  for (const user of users) {
    logger.log(level.info, `Every 7 day cron user=${user}`);
    const message = `Hey ${user.name}, Learn to synchronize your mind, body, and soul to live a happy and fulfilled life. Taste the personalized therapeutic experience.`
  }
}, { scheduled: true });

cron.schedule('* * * 1 * *', async () => {
  const users = await User.get({ status: 1 });
  for (const user of users) {
    logger.log(level.info, `Every month cron user=${user}`);
    const message = `Hey ${user.name}, Make the move and live the life you desire. Click here to restart your journey toward Mental, Physical and Emotional wellness. We miss you.`
  }
}, { scheduled: true });