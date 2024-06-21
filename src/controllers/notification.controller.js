import {level, logger} from "../config/logger.js";
import {beautify, internalServerError, okResponse} from "../shared/utils/utility.js";
import Notification from "../models/notification.model.js";
import messages from "../shared/constant/messages.const.js";

export const getNotification = async (req, res) => {
    try {
        const { query, params } = req;
        const { option = {} } = query;
        const { userId } = params;
        option.sort = "-1";
        logger.log(level.info, `getAllNotification options=${beautify(option)}`);
        const filter = {"$expr": {"$in": [ userId , "$user_ids"]}};
        logger.log(level.info, `getAllNotification filter=${beautify(filter)}`);
        const notification = await Notification.get(filter, null, option);
        const total = await Notification.count(filter);
        const data = notification?.map(item => ({
            schedule_time: item?.schedule_time,
            title: item?.title,
            description: item?.description,
            image: item?.image,
            created_at: item?.created_at,
            updated_at: item?.updated_at,
            notification_id: item?.notification_id
        }));
        return okResponse(res, messages.record_fetched, data, total);
    } catch (error) {
        logger.log(level.error, `getAllNotificationByAdmin Error: ${beautify(error.message)}`);
        return internalServerError(res, error)
    }
};