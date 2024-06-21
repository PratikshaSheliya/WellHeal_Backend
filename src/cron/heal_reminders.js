import cron from 'node-cron'

import User from '../models/user.model.js';

cron.schedule('0 0 0/24 * * *', async () => {
  const users = await User.get({ status: 1 });
  for (const user of users) {
    logger.log(level.info, `Every 24 hours cron user=${user}`);
    const message = `Hey ${user.name}, It’s time to move one step ahead in your self-growth journey. Click here to resume your (session minutes) therapy session for ${"Subcategory"}. `
  }
}, { scheduled: true });

cron.schedule('0 0 0/48 * * *', async () => {
  const users = await User.get({ status: 1 });
  for (const user of users) {
    logger.log(level.info, `Every 48 hours cron user=${user}`);
    const message = `Hey ${user.name}, It’s been a long day without you. Let’s move ahead to make your present and future better. Time for your next ${"Subcategory Title"} session.`
  }
}, { scheduled: true });

cron.schedule('* * */4 * * *', async () => {
  const users = await User.get({ status: 1 });
  for (const user of users) {
    logger.log(level.info, `Every 4 day cron user=${user}`);
    const message = `Hey ${user.name}, A new way of life awaits you. Stop being a victim and become a victor. Resume your journey and take the next session for ${"Subcategory Title"}.`
  }
}, { scheduled: true });

cron.schedule('* * */7 * * *', async () => {
  const users = await User.get({ status: 1 });
  for (const user of users) {
    logger.log(level.info, `Every 7 day cron user=${user}`);
    const message = `Hey ${user.name}, Discover and retrieve the power back. Let your light shine bright. Take a step towards mental freedom and restart your sessions today.`
  }
}, { scheduled: true });