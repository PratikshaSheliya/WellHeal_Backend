import HTTPStatus from "http-status";
import messages from "../shared/constant/messages.const.js";
import { UPLOAD_PATH } from "../shared/constant/application.const.js";
import Quote from "../models/quote.model.js";
import { logger, level } from "../config/logger.js";
import { internalServerError, beautify, okResponse, badRequestError, toObjectId, generateRandomString, paramMissingError, parseSearchOptions } from "../shared/utils/utility.js";
import { returnOnExist, returnOnNotExist } from "../shared/services/database/query.service.js";
import { IMAGE_EXTENSIONS } from "../shared/constant/types.const.js";
import { getSignedUrl, removeFileFromS3, uploadFileToS3 } from "../shared/services/file-upload/aws-s3.service.js";
import Path from "path";
import moment from "moment";

const deletedCondition = { is_deleted: false };

async function uploadFileAndUpdateImageURL(s3Location, file, filter) {
    uploadFileToS3(process.env.Aws_Bucket_Name, s3Location, file).then(async (result) => {
        await Quote.update(filter, { image: s3Location });
    }, (err) => {
        logger.log(level.error, `updateQuoteDetail err=${beautify(err.message)}`);
    });
}

export const createQuote = async (req, res) => {
    try {
        const { body, file } = req;
        const { description = "", schedule = null, users = [] } = body;
        const option = {};
        logger.log(level.info, `createQuote body=${beautify(req.body)}`);

        if (!file) {
            logger.log(level.info, 'createQuote no file selection found error');
            return paramMissingError(res, messages.missing_key.replace("{dynamic}", "Image File"));
        }

        if (users.length <= 0) {
            logger.log(level.error, `createQuote error: Invalid Length of Users in a body`);
            return paramMissingError(res, messages.missing_key.replace("{dynamic}", "User"));
        }

        if(!schedule) {
            logger.log(level.info, 'createQuote schedule found error');
            return paramMissingError(res, messages.missing_key.replace("{dynamic}", "Schedule"));
        }
        const filter = { schedule: moment(schedule).toISOString() };
        if(schedule) {
            const data = await Quote.get(filter, null, option);
            if(data.length > 0) {
                logger.log(level.info, 'createQuote schedule is already exist');
                return badRequestError(res, messages.quote_schedule);
            }
        }

        const quoteS3Folder = process.env.Aws_Upload_Path_For_Quote;
        const filePath = Path.parse(file.originalname);
        const fileName = generateRandomString();

        if (!(Object.values(IMAGE_EXTENSIONS).includes(filePath.ext))) {
            logger.log(level.info, 'createSubCategory invalid file selection error');
            return badRequestError(res, messages.invalid_file_selected);
        }

        const quote = await Quote.add({ description, schedule: moment(schedule).toISOString(), user_ids: users });
        if (!quote) {
            logger.log(level.info, `createQuote Error`);
            return badRequestError(res, messages.invalid_input, null, HTTPStatus.NOT_FOUND)
        }
        const s3Location = `${quoteS3Folder}${fileName}${filePath.ext}`;
        uploadFileToS3(process.env.Aws_Bucket_Name, s3Location, file).then((result, error) => {
            if (!error) {
                Quote.update({ _id: quote._id }, { image: s3Location });
            } else {
                logger.log(level.error, `createQuote Error : Image upload : ${beautify(error)}`);
            }
        });

        quote['image'] = await getSignedUrl(process.env.Aws_Bucket_Name, s3Location);

        logger.log(level.info, `createQuote =${beautify(quote)}`);

        return okResponse(res, messages.created.replace("{dynamic}", "Quote"), quote);
    } catch (error) {
        logger.log(level.error, `createQuote Error: ${beautify(error.message)}`);
        return internalServerError(res, error);
    }
};

export const updateQuote = async (req, res) => {
    try {
        const {params, body, file } = req;
        const {quoteId} = params
        const { description, schedule, users } = body;
        logger.log(level.info, `update Quote body=${beautify(req.body)}`)
        const filter = { _id: quoteId };

        // Preparing Payload to update in DB
        const payload = {};
        description ? payload['description'] = description : null;
        schedule ? payload['schedule'] = schedule : null;
        users ? payload['user_ids'] = users : [];

        logger.log(level.info, `updateQuote quoteId=${quoteId} body=${beautify(body)}`);
        const updatedQuote = await Quote.update(filter, payload);
        logger.log(level.info, `updateQuote updatedQuote=${beautify(updatedQuote)}`)
               
        let s3Location;
        if (file) {
          const filePath = Path.parse(file.originalname);
          const fileName = generateRandomString();
          s3Location = `${UPLOAD_PATH.Quote}${fileName}${filePath.ext}`;
    
          if (!(Object.values(IMAGE_EXTENSIONS).includes(filePath.ext))) {
            logger.log(level.info, 'updatequoteDetail: invalid file selection error')
            return badRequestError(res, messages.invalid_file_selected);
          }
    
          const [getQuote] = await Quote.get(filter)
          if (getQuote && getQuote.image) {
            removeFileFromS3(process.env.Aws_Bucket_Name, getQuote.image);
          }
          uploadFileAndUpdateImageURL(s3Location, file, filter);
        }
        if (s3Location) {
            // set this due to pervent old urlsigning
            updatedQuote['image'] = await getSignedUrl(process.env.Aws_Bucket_Name, s3Location);
        }
      
        return await okResponse(res, messages.updated.replace("{dynamic}", "Quote"), updatedQuote);
    } catch (error) {
        logger.log(level.error, `createQuote Error: ${beautify(error.message)}`);
        return internalServerError(res, error);
    }
};

export const deleteQuote = async (req, res) => {
    try {
        const { params } = req;
        const { quoteId } = params;

        logger.log(level.info, `deleteQuote params=${beautify(params)}`);
        const question = await Quote.delete({ _id: quoteId });
        if (!question) {
            logger.log(level.info, 'deleteQuote error')
            return badRequestError(res, messages.invalid_input);
        }
        logger.log(level.info, `deleteQuote question=${beautify(question)}`);
        return okResponse(res, messages.deleted.replace("{dynamic}", "Quote"));

    } catch (error) {
        logger.log(level.error, `deleteQuote Error: ${beautify(error.message)}`);
        return internalServerError(res, error)
    }
};

export const getAllQuote = async (req,res) => {
    try {
        const { query } = req;
        const { option = {} } = query;
        const { sort = { created_at: -1 } } = option;
        option['sort'] = sort;

        logger.log(level.info, `Admin getAllQuotes options=${beautify(option)}`);

        const filter = await parseSearchOptions(option);
        logger.log(level.info, `getAllQuotes filter=${beautify(filter)}`);
        const users = await Quote.get(filter, null, option);
        const count = await users.length;
        for (let user of users) {
            user.image = await getSignedUrl(process.env.Aws_Bucket_Name, user?.image);
        }
        return okResponse(res, messages.record_fetched, users, count);
    } catch (error) {
        logger.log(level.error, `Admin getAllQuotes Error : ${beautify(error.message)}`);
        return internalServerError(res, error)
    }
};

export const getQuoteImage = async (req, res) => {
    try {
        const userId = req['currentUserId'];
        const {option = {}} = req.query;
        const filter = {};
        const quotes = await Quote.get(filter, null, option);
        if (quotes.length > 0) {
            const currentData = quotes?.map(item => {
                console.log("===",moment(item.schedule).format("YYYY-MM-DD"));
                console.log("---",moment(new Date()).format("YYYY-MM-DD"))
            });
            const currentDataQuote = quotes?.find(item => moment(item.schedule).format("YYYY-MM-DD") === moment(new Date()).format("YYYY-MM-DD"));
            if(currentDataQuote?._id) {
                let finalQuote = {};
                if (currentDataQuote.user_ids.includes(userId)) {
                    finalQuote = currentDataQuote
                }
                if (finalQuote?._id) {
                    finalQuote = {
                        _id: finalQuote?._id,
                        image: finalQuote?.image,
                        description: finalQuote?.description,
                        schedule: finalQuote?.schedule,
                        created_at: finalQuote?.created_at,
                        updated_at: finalQuote?.updated_at,
                        id: finalQuote?.id
                    }
                } else {
                    return okResponse(res, messages.user_missing);
                }
                if (finalQuote?.image) {
                    finalQuote['image'] = await getImageLink(finalQuote?.image)
                }
                return okResponse(res, messages.record_fetched, finalQuote);
            } else {
                return okResponse(res, messages.quote_missing);
            }
        } else {
            return okResponse(res, messages.quote_missing);
        }
    } catch (error) {
        logger.log(level.error, `getQuotes Error: ${beautify(error.message)}`);
        return internalServerError(res, error)
    }
};

const getImageLink = async (item) => {
    return await getSignedUrl(process.env.Aws_Bucket_Name, item);
};