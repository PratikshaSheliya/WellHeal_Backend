import httpStatus from "http-status";
import logger, { level } from "../../../config/logger.js";
import messages from "../../constant/messages.const.js";
import { badRequestError, unauthorizedError } from "../../utils/utility.js";

export const isExistOrNot = async (modal, filter, res, what, message = messages.invalid_input) => {
    const isExist = await modal.isExist(filter);
    if (!isExist) {
        logger.log(level.error, `${what} not exist.`)
        return unauthorizedError(res, message, null, httpStatus.UNAUTHORIZED);
    } else {
        return false;
    }
}

export const returnOnNotExist = async (modal, filter, res, what, message = messages.invalid_input) => {
    const isExist = await modal.isExist(filter);
    if (!isExist) {
        logger.log(level.error, `${what} not exist.`)
        return badRequestError(res, message, null, httpStatus.NOT_FOUND);
    } else {
        return false;
    }
}

export const returnOnExist = async (modal, filter, res, what, message = messages.invalid_input) => {
    const isExist = await modal.isExist(filter);
    if (isExist) {
        logger.log(level.error, `${what} already exist.`)
        return badRequestError(res, message, null, httpStatus.NOT_ACCEPTABLE);
    } else {
        return false;
    }
}