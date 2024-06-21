import moment from 'moment'
import scheduleNotification from "../models/schedule_notification.model.js";
import {parseSearchOptions} from "../shared/utils/utility.js";
import UserToken from "../models/user_token.model.js";
import {level, logger} from "../config/logger.js";
import {beautify} from "../shared/utils/utility.js";
import {sendPushNotification} from "../shared/services/firebase/send_notification.service.js";
import Notification from "../models/notification.model.js";

export const scheduleNotificationByCron = async () => {
    const option = {};
    const filter = await parseSearchOptions(option);
    const notification = await scheduleNotification.get(filter, null, option);
    notification?.map(async item => {
        if ((moment(item?.schedule_time).format('MM/DD/YYYY h:mm a') === moment(new Date()).format('MM/DD/YYYY h:mm a')) && !item?.isSend) {
            const userTokens = await UserToken.get({user_id: {$in: [...item?.user_ids]}, is_loggedOut: false});
            const deviceTokens = userTokens.map(token => token.device_token);
            logger.log(level.info, `sendNotificationToUser notification Tokens = ${beautify(deviceTokens)}`);
            const payload = {
                notification: {
                    title: item?.title,
                    body: item?.description,
                    image: item?.image
                }
            };
            const result = await sendPushNotification(deviceTokens, payload, "high");
            let notification;
            if (result) {
                notification = await Notification.add({
                    user_ids: [...item?.user_ids],
                    title: item?.title,
                    description: item?.description,
                    image: item?.image,
                    schedule_time: item?.schedule_time
                });
            }
            const update = await scheduleNotification.update(
                { _id: item?._id },
                {
                    isSend: true
                }
            );
        }
    });
};