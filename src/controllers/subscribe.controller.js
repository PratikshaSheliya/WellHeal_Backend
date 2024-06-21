import Path from "path";
import HTTPStatus from "http-status";
import {level, logger} from "../config/logger.js";
import {
    badRequestError,
    beautify,
    generateRandomString,
    internalServerError,
    okResponse,
    paramMissingError
} from "../shared/utils/utility.js";
import messages from "../shared/constant/messages.const.js";
import {IMAGE_EXTENSIONS} from "../shared/constant/types.const.js";
import {getSignedUrl, uploadFileToS3} from "../shared/services/file-upload/aws-s3.service.js";
import SubscribeCard from "../models/subscribeCard.model.js";
import {parseSearchOptions} from "../shared/utils/utility.js";
import {UPLOAD_PATH} from "../shared/constant/application.const.js";
import {removeFileFromS3} from "../shared/services/file-upload/aws-s3.service.js";

async function uploadFileAndUpdateImageURL(s3Location, file, filter) {
    uploadFileToS3(process.env.Aws_Bucket_Name, s3Location, file).then(async (result) => {
        await SubscribeCard.update(filter, { image: s3Location });
    }, (err) => {
        logger.log(level.error, `updateSubscribeCard err=${beautify(err.message)}`);
    });
}

export const createSubscribeCard = async (req, res) => {
    try {
        const { body, file } = req;
        const { description = "", title = null } = body;
        const option = {};
        logger.log(level.info, `createSubscribeCard body=${beautify(req.body)}`);

        if (!file) {
            logger.log(level.info, 'createSubscribeCard no file selection found error');
            return paramMissingError(res, messages.missing_key.replace("{dynamic}", "Image File"));
        }
        if (!title) {
            logger.log(level.info, 'createSubscribeCard title found error');
            return paramMissingError(res, messages.missing_key.replace("{dynamic}", "title"));
        }
        if (!description) {
            logger.log(level.info, 'createSubscribeCard description found error');
            return paramMissingError(res, messages.missing_key.replace("{dynamic}", "description"));
        }

        const subscribeCardS3Folder = process.env.Aws_Upload_Path_For_SubscribeCard;
        const filePath = Path.parse(file.originalname);
        const fileName = generateRandomString();

        if (!(Object.values(IMAGE_EXTENSIONS).includes(filePath.ext))) {
            logger.log(level.info, 'createSubscribeCard invalid file selection error');
            return badRequestError(res, messages.invalid_file_selected);
        }

        const subscribeCard = await SubscribeCard.add({ description, title });
        if (!subscribeCard) {
            logger.log(level.info, `createSubscribeCard Error`);
            return badRequestError(res, messages.invalid_input, null, HTTPStatus.NOT_FOUND)
        }
        const s3Location = `${subscribeCardS3Folder}${fileName}${filePath.ext}`;
        uploadFileToS3(process.env.Aws_Bucket_Name, s3Location, file).then((result, error) => {
            if (!error) {
                SubscribeCard.update({ _id: subscribeCard._id }, { image: s3Location });
            } else {
                logger.log(level.error, `createSubscribeCard Error : Image upload : ${beautify(error)}`);
            }
        });

        subscribeCard['image'] = await getSignedUrl(process.env.Aws_Bucket_Name, s3Location);

        logger.log(level.info, `createSubscribeCard =${beautify(subscribeCard)}`);

        return okResponse(res, messages.created.replace("{dynamic}", "Quote"), subscribeCard);
    } catch (error) {
        logger.log(level.error, `createSubscribeCard Error: ${beautify(error.message)}`);
        return internalServerError(res, error);
    }
};

export const getSubscribeCard = async (req,res) => {
    try {
        const { query } = req;
        const { option = {} } = query;

        logger.log(level.info, `Admin getSubscribeCard options=${beautify(option)}`);
        const filter = await parseSearchOptions(option);
        logger.log(level.info, `getSubscribeCard filter=${beautify(filter)}`);
        const subscribeCard = await SubscribeCard.get(filter, null, option);
        const count = await subscribeCard.length;
        for (let card of subscribeCard) {
            card.image = await getSignedUrl(process.env.Aws_Bucket_Name, card?.image);
        }
        return okResponse(res, messages.record_fetched, subscribeCard, count);
    } catch (error) {
        logger.log(level.error, `Admin getSubscribeCard Error : ${beautify(error.message)}`);
        return internalServerError(res, error)
    }
};

export const updateSubscribeCard = async (req, res) => {
    try {
        const {params, body, file } = req;
        const {subscribeCardId} = params;
        const { description, title } = body;
        logger.log(level.info, `update SubscribeCard body=${beautify(req.body)}`);
        const filter = { _id: subscribeCardId };

        const payload = {};
        description ? payload['description'] = description : null;
        title ? payload['title'] = title : null;

        logger.log(level.info, `updateSubscribeCard quoteId=${subscribeCardId} body=${beautify(body)}`);
        const updatedSubscribeCard = await SubscribeCard.update(filter, payload);
        logger.log(level.info, `updateSubscribeCard updateSubscribeCard=${beautify(updatedSubscribeCard)}`)

        let s3Location;
        if (file) {
            const filePath = Path.parse(file.originalname);
            const fileName = generateRandomString();
            s3Location = `${UPLOAD_PATH.SubscribeCard}${fileName}${filePath.ext}`;

            if (!(Object.values(IMAGE_EXTENSIONS).includes(filePath.ext))) {
                logger.log(level.info, 'updateSubscribeCardDetail: invalid file selection error');
                return badRequestError(res, messages.invalid_file_selected);
            }

            const [getSubscribeCard] = await SubscribeCard.get(filter);
            if (getSubscribeCard && getSubscribeCard.image) {
                removeFileFromS3(process.env.Aws_Bucket_Name, getSubscribeCard.image);
            }
            uploadFileAndUpdateImageURL(s3Location, file, filter);
        }
        if (s3Location) {
            updatedSubscribeCard['image'] = await getSignedUrl(process.env.Aws_Bucket_Name, s3Location);
        }

        return await okResponse(res, messages.updated.replace("{dynamic}", "SubscribeCard"), updatedSubscribeCard);
    } catch (error) {
        logger.log(level.error, `updateSubscribeCardDetail Error: ${beautify(error.message)}`);
        return internalServerError(res, error);
    }
};

export const deleteSubscribeCard = async (req, res) => {
    try {
        const { params } = req;
        const { subscribeCardId } = params;

        logger.log(level.info, `deleteSubscribeCardDetail params=${beautify(params)}`);
        const subscribeCard = await SubscribeCard.delete({ _id: subscribeCardId });
        if (!subscribeCard) {
            logger.log(level.info, 'deleteSubscribeCardDetail error');
            return badRequestError(res, messages.invalid_input);
        }
        logger.log(level.info, `deleteSubscribeCardDetail question=${beautify(subscribeCard)}`);
        return okResponse(res, messages.deleted.replace("{dynamic}", "subscribeCard"));

    } catch (error) {
        logger.log(level.error, `deleteSubscribeCardDetail Error: ${beautify(error.message)}`);
        return internalServerError(res, error)
    }
};

export const getUserSubscribeCard = async (req, res) => {
    try {
        const { query } = req;
        const { option = {} } = query;

        logger.log(level.info, `Admin getSubscribeCard options=${beautify(option)}`);
        const filter = await parseSearchOptions(option);
        logger.log(level.info, `getSubscribeCard filter=${beautify(filter)}`);
        const subscribeCard = await SubscribeCard.get(filter, null, option);
        const count = await SubscribeCard.count(filter);
        for (let card of subscribeCard) {
            card.image = await getSignedUrl(process.env.Aws_Bucket_Name, card?.image);
        }
        return okResponse(res, messages.record_fetched, subscribeCard, count);
    } catch (error) {
        logger.log(level.error, `Admin getSubscribeCard Error : ${beautify(error.message)}`);
        return internalServerError(res, error)
    }
};