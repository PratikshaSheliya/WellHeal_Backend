import moment from "moment";
import logger, { level } from "../config/logger.js";
import Coupon from "../models/coupon.model.js";
import User from "../models/user.model.js";
import messages from "../shared/constant/messages.const.js";
import { COUPON_FOR_WHO, COUPON_TYPE, USER_PRO_STATUS } from "../shared/constant/types.const.js";
import { badRequestError, beautify, internalServerError, loop, makeNumericId, okResponse, SendEmail, toObjectId, parseSearchOptions } from "../shared/utils/utility.js";

export const createCoupon = async (req, res) => {
    try {
        return okResponse(res, messages.record_fetched);
    } catch (error) {
        logger.log(level.error, `getFavouriteTherapies Error: ${beautify(error.message)}`);
        return internalServerError(res, error);
    }
}

export const generateTrialCoupon = async (req, res) => {
    try {
        const { body } = req;
        const { email } = body;

        const payload = {
            user_id: req['currentUserId'],
            coupon_type: COUPON_TYPE.TRIAL_COUPON,
            coupon_for: COUPON_FOR_WHO.SINGLE_USER,
            expire_time: 14,
            coupon_code: `WellHeal@${await makeNumericId(3)}`
        };
        logger.log(level.info, `generateTrialCoupon payload=${beautify(payload)}`);
        const filter = { user_id: req['currentUserId'], coupon_type: COUPON_TYPE.TRIAL_COUPON, coupon_for: COUPON_FOR_WHO.SINGLE_USER }
        const [coupon] = await Coupon.get(filter);
        let c;
        if (coupon) {
            c = await Coupon.update(filter, { coupon_code: payload.coupon_code });
        } else {
            c = await Coupon.add(payload)
        }
        let message = messages.created.replace("{dynamic}", "Coupon");
        if (email) {
            const [user] = await User.get({ _id: req['currentUserId'], $or: [{ is_deleted: false }, { is_deleted: { $exists: false } }] });
            SendEmail(email, 'trialCoupon', payload.coupon_code, user?.name || 'There');
            message = messages.email_sent;
        }
        return okResponse(res, message, c);
    } catch (error) {
        logger.log(level.error, `generateTrialCoupon Error: ${beautify(error.message)}`);
        return internalServerError(res, error);
    }
}

export const verifyTrialCoupon = async (req, res) => {

    const { body } = req;
    const { coupon_code } = body

    const filter = {
        user_id: req['currentUserId'],
        coupon_type: COUPON_TYPE.TRIAL_COUPON,
        coupon_for: COUPON_FOR_WHO.SINGLE_USER,
        coupon_code: coupon_code
    }

    const existingCoupon = await Coupon.get(filter);
    if (existingCoupon.length > 0) {
        let updateFilter = { _id: toObjectId(req['currentUserId']) }
        const [user] = await User.get(updateFilter)
        if (!user.trial_redeem_time) {
            const updatedUser = await User.update(updateFilter, { trial_redeem_time: new Date().toISOString() })
            let userDoc = JSON.parse(JSON.stringify(updatedUser))
            delete userDoc.password;
            userDoc[USER_PRO_STATUS.TRIAL] = true;
            userDoc[USER_PRO_STATUS.TRIAL_EXPIRED] = false;
            return okResponse(res, messages.user_verified_success, userDoc)
        } else {
            logger.log(level.error, `verifyTrialCoupon error: ${messages.already_used_code}`);
            return badRequestError(res, messages.already_used_code)
        }
    } else {
        logger.log(level.error, `verifyTrialCoupon error: ${messages.invalid_key.replace("{dynamic}", "Trial Coupon Code.")}`);
        return badRequestError(res, messages.invalid_key.replace("{dynamic}", "Trial Coupon Code."))
    }
}

export const updateTrialCoupons = async (req, res) => {
    try {
        const { body } = req;
        const { expire_time } = body;

        logger.log(level.info, `updateTrialCoupons body: ${beautify(body)}`);

        const filter = {
            coupon_type: COUPON_TYPE.TRIAL_COUPON,
            coupon_for: COUPON_FOR_WHO.SINGLE_USER,
        }
        const list = await Coupon.get(filter);
        if (list.length > 0) {
            loop(list, async (record) => {
                const updated = await Coupon.update({ _id: record._id }, { expire_time })
                logger.log(level.info, `updated Trial Coupon: ${updated._id} expiry: ${expire_time} Days`);
            })
        }
        return okResponse(res, messages.updated.replace("{dynamic}", "Coupons"));
    } catch (error) {
        logger.log(level.error, `getFavouriteTherapies Error: ${beautify(error.message)}`);
        return internalServerError(res, error);
    }
}

export const getCoupons = async (req, res) => {
    try {
        const { query } = req;
        const { option = {} } = query;
        const { sort = { created_at: -1 } } = option;
        option['sort'] = sort;

        const filter = await parseSearchOptions(option);
        const coupon = await Coupon.get(filter, null, option, { path: 'user' });
        const total = await coupon.length;
        let finalList = JSON.parse(JSON.stringify(coupon))
        finalList = finalList.map(coupon => {
            if (coupon?.user?.trial_redeem_time) {
                var expire_date = moment(coupon.user.trial_redeem_time).add(coupon.expire_time, 'days');
                coupon.user['trial_expire_date'] = expire_date;
                coupon.user['trial_expire_time'] = moment(coupon.created_at).add(coupon.expire_time, 'days').toDate();
            }
            return coupon;

        })
        logger.log(level.info, `coupons = ${beautify(finalList)}`);
        return okResponse(res, messages.record_fetched, finalList, total);

    } catch (error) {
        logger.log(level.error, `generateTrialCoupon Error: ${beautify(error.message)}`);
        return internalServerError(res, error);
    }
}