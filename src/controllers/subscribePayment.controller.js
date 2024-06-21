import HTTPStatus from "http-status";
import SubscribePaymentCard from "../models/subscribePaymentCard.model.js";
import {level, logger} from "../config/logger.js";
import {badRequestError, beautify, internalServerError, okResponse, paramMissingError, parseSearchOptions} from "../shared/utils/utility.js";
import messages from "../shared/constant/messages.const.js";

export const createSubscribePaymentCard = async (req, res) => {
    try {
        const { body } = req;
        logger.log(level.info, `createSubscribePaymentCard body=${beautify(req.body)}`)
        const { month = null, price = null, recommended = null } = body;

        if (!month) {
            logger.log(level.info, 'createSubscribePaymentCard month found error');
            return paramMissingError(res, messages.missing_key.replace("{dynamic}", "month"));
        }
        if (!price) {
            logger.log(level.info, 'createSubscribePaymentCard price found error');
            return paramMissingError(res, messages.missing_key.replace("{dynamic}", "price"));
        }

        const subscribePaymentCard = await SubscribePaymentCard.add({ month, price, recommended });
        if (!subscribePaymentCard) {
            logger.log(level.info, `subscribePaymentCard Error`)
            return badRequestError(res, messages.invalid_input, null, HTTPStatus.NOT_FOUND)
        }
        logger.log(level.info, `createSubscribePaymentCard category=${beautify(subscribePaymentCard)}`);
        return okResponse(res, messages.created.replace("{dynamic}", "SubscribePaymentCard"), subscribePaymentCard);
    } catch (error) {
        logger.log(level.error, `createSubscribePaymentCard Error: ${beautify(error.message)}`);
        return internalServerError(res, error);
    }
};

export const getSubscribePaymentCard = async (req,res) => {
    try {
        const { query } = req;
        const { option = {} } = query;

        logger.log(level.info, `Admin getSubscribePaymentCard options=${beautify(option)}`);
        const filter = await parseSearchOptions(option);
        logger.log(level.info, `getSubscribePaymentCard filter=${beautify(filter)}`);
        const subscribeCard = await SubscribePaymentCard.get(filter, null, option);
        const count = await subscribeCard.length;

        return okResponse(res, messages.record_fetched, subscribeCard, count);
    } catch (error) {
        logger.log(level.error, `Admin getSubscribePaymentCard Error : ${beautify(error.message)}`);
        return internalServerError(res, error)
    }
};

export const updateSubscribePaymentCard = async (req, res) => {
    try {
        const {params, body } = req;
        const { subscribePaymentCardId } = params;
        const { month, price, recommended } = body;
        logger.log(level.info, `update SubscribePaymentCard body=${beautify(req.body)}`);
        const filter = { _id: subscribePaymentCardId };

        const payload = {};
        month ? payload['month'] = month : null;
        price ? payload['price'] = price : null;
        payload['recommended'] = recommended;

        logger.log(level.info, `updateSubscribePaymentCard subscribePaymentCardId=${subscribePaymentCardId} body=${beautify(body)}`);
        const updatedSubscribePaymentCard = await SubscribePaymentCard.update(filter, payload);
        logger.log(level.info, `updateSubscribePaymentCard subscribePaymentCardId=${beautify(updatedSubscribePaymentCard)}`)

        return await okResponse(res, messages.updated.replace("{dynamic}", "SubscribePaymentCard"), updatedSubscribePaymentCard);
    } catch (error) {
        logger.log(level.error, `updateSubscribePaymentCard Error: ${beautify(error.message)}`);
        return internalServerError(res, error);
    }
};

export const deleteSubscribePaymentCard = async (req, res) => {
    try {
        const { params } = req;
        const { subscribePaymentCardId } = params;

        logger.log(level.info, `deleteSubscribePaymentCardDetail params=${beautify(params)}`);
        const subscribePaymentCard = await SubscribePaymentCard.delete({ _id: subscribePaymentCardId });
        if (!subscribePaymentCard) {
            logger.log(level.info, 'deleteSubscribePaymentCardDetail error');
            return badRequestError(res, messages.invalid_input);
        }
        logger.log(level.info, `deleteSubscribePaymentCardDetail question=${beautify(subscribePaymentCard)}`);
        return okResponse(res, messages.deleted.replace("{dynamic}", "subscribePaymentCard"));

    } catch (error) {
        logger.log(level.error, `deleteSubscribePaymentCardDetail Error: ${beautify(error.message)}`);
        return internalServerError(res, error)
    }
};

export const getUserSubscribePaymentCard = async (req,res) => {
    try {
        const { query } = req;
        const { option = {} } = query;

        logger.log(level.info, `Admin getSubscribePaymentCard options=${beautify(option)}`);
        const filter = await parseSearchOptions(option);
        logger.log(level.info, `getSubscribePaymentCard filter=${beautify(filter)}`);
        const subscribeCard = await SubscribePaymentCard.get(filter, null, option);
        const count = await SubscribePaymentCard.count(filter);

        return okResponse(res, messages.record_fetched, subscribeCard, count);
    } catch (error) {
        logger.log(level.error, `Admin getSubscribePaymentCard Error : ${beautify(error.message)}`);
        return internalServerError(res, error)
    }
};