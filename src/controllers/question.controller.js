import Path from "path";
import logger, { level } from "../config/logger.js";
import Question from "../models/question.model.js";
import User from "../models/user.model.js";
import UserAnswers from "../models/user_answers.model.js";
import messages from "../shared/constant/messages.const.js";
import { IMAGE_EXTENSIONS, QUESTION_TYPES } from "../shared/constant/types.const.js";
import { returnOnNotExist } from "../shared/services/database/query.service.js";
import { getSignedUrl, uploadFileToS3 } from "../shared/services/file-upload/aws-s3.service.js";
import { badRequestError, beautify, generateRandomString, internalServerError, okResponse, paramMissingError, toObjectId, parseSearchOptions } from "../shared/utils/utility.js";

export const createQuestion = async (req, res) => {
    try {
        const { body, file } = req;
        const { question, question_type, combination_code_ids } = body;
        logger.log(level.info, `createQuestion body=${beautify(body)}`)

        if (!file) {
            logger.log(level.info, 'createQuestion no file selection found error')
            return paramMissingError(res, messages.missing_key.replace("{dynamic}", "File"));
        }

        const s3Folder = process.env.Aws_Upload_Path_For_Question;
        const filePath = Path.parse(file.originalname);
        const fileName = generateRandomString();

        if (!(Object.values(IMAGE_EXTENSIONS).includes(filePath.ext))) {
            logger.log(level.info, 'createQuestion invalid file selection error')
            return badRequestError(res, messages.invalid_file_selected);
        }

        const createdQuestion = await Question.add({ question, question_type, combination_code_ids });
        logger.log(level.info, `createQuestion createdQuestion=${beautify(createdQuestion)}`)

        const s3Location = `${s3Folder}${createdQuestion.id}/thumbnail/${fileName}${filePath.ext}`;
        uploadFileToS3(process.env.Aws_Bucket_Name, s3Location, file).then((result, error) => {
            if (!error) {
                Question.update({ _id: createdQuestion._id }, { thumbnail_url: s3Location });
            } else {
                logger.log(level.error, `createQuestion Error : Thumbnail upload : ${beautify(error)}`);
            }
        });

        createdQuestion['thumbnail_url'] = await getSignedUrl(process.env.Aws_Bucket_Name, s3Location);

        if (createdQuestion) {
            return okResponse(res, messages.created.replace("{dynamic}", "Question"), createdQuestion);
        } else {
            logger.log(level.error, `createQuestion Error`)
            return badRequestError(res, messages.invalid_input);
        }
    } catch (error) {
        logger.log(level.info, `createQuestion Error=${beautify(error.message)}`)
        return internalServerError(res, error)
    }
}

export const updateQuestion = async (req, res) => {
    try {
        const { params, body, file = null } = req;
        const { questionId } = params;
        const { question, combination_code_ids } = body;
        const filter = { _id: questionId };

        const s3Folder = process.env.Aws_Upload_Path_For_Question;
        let filePath, fileName, s3Location;
        if (file) {
            filePath = Path.parse(file.originalname);
            fileName = generateRandomString();
            if (!(Object.values(IMAGE_EXTENSIONS).includes(filePath.ext))) {
                logger.log(level.info, 'updateQuestion invalid file selection error')
                return badRequestError(res, messages.invalid_file_selected);
            }
        }

        const notExist = await returnOnNotExist(Question, filter, res, "Question", messages.not_exist.replace("{dynamic}", "Question"));
        if (notExist) return;


        // Preparing Payload to update in DB
        const payload = {};
        if (question) payload['question'] = question;
        // if(combination_code_ids) payload['combination_code_ids'] = combination_code_ids;
        logger.log(level.info, `updateQuestion questionId=${questionId}, Payload=${beautify(payload)}`)


        const updatedQuestion = await Question.update(filter, payload);
        logger.log(level.info, `updateQuestion updatedQuestion=${beautify(updatedQuestion)}`)
        if (!updatedQuestion) {
            logger.log(level.info, `updateQuestion Error`)
            return badRequestError(res, messages.invalid_input);
        }

        if (file) {
            s3Location = `${s3Folder}${questionId}/thumbnail/${fileName}${filePath.ext}`;
            logger.log(level.info, `s3Location : ${s3Location}`);
            uploadFileToS3(process.env.Aws_Bucket_Name, s3Location, file).then((result, error) => {
                if (!error) {
                    Question.update(filter, { thumbnail_url: s3Location });
                } else {
                    logger.log(level.error, `updateQuestion Error : Thumbnail upload : ${beautify(error)}`);
                }
            });
            updatedQuestion['thumbnail_url'] = await getSignedUrl(process.env.Aws_Bucket_Name, s3Location);
        }

        return okResponse(res, messages.updated.replace("{dynamic}", "Question"), updatedQuestion)
    } catch (error) {
        logger.log(level.error, `updateQuestion Error = ${beautify(error)}`);
        return internalServerError(res, error)
    }
}

export const getSplashScreenQuestion = async (req, res) => {
    try {
        const { query } = req;
        const { option = {} } = query;
        const { sort = { created_at: -1 } } = option;
        option['sort'] = sort;

        const searchFilter = await parseSearchOptions(option);
        logger.log(level.info, `getSplashScreenQuestion option=${beautify(option)}`);

        const filter = { question_type: QUESTION_TYPES.SPLASH_QUESTION, ...searchFilter  }
        const populate = {
            path: "combination_codes"
        }
        const questions = await Question.get(filter, { '_id': 1, "question": 1, "combination_code_ids": 1, "thumbnail_url": 1 }, option, populate);
        const total = questions.length;
        logger.log(level.info, `Questions = ${beautify(questions)}`);
        return okResponse(res, messages.record_fetched, questions, total);
    } catch (error) {
        logger.log(level.error, `getSplashScreenQuestion Error: ${beautify(error.message)}`);
        return internalServerError(res, error)
    }
}

export const deleteQuestion = async (req, res) => {
    try {
        const { params } = req;
        const { questionId } = params;

        logger.log(level.info, `deleteQuestion params=${beautify(params)}`);
        const question = await Question.delete({ _id: questionId });
        if (!question) {
            logger.log(level.info, 'deleteQuestion error')
            return badRequestError(res, messages.invalid_input);
        }
        logger.log(level.info, `deleteQuestion question=${beautify(question)}`);
        return okResponse(res, messages.deleted.replace("{dynamic}", "Question"));

    } catch (error) {
        logger.log(level.error, `getSplashScreenQuestion Error: ${beautify(error.message)}`);
        return internalServerError(res, error)
    }
}

export const createSplashScreenAnswer = async (req, res) => {
    try {
        const { body } = req;
        logger.log(level.info, `createSplashScreenAnswer body=${beautify(body)}`);

        if (!Array.isArray(body)) {
            return badRequestError(res, messages.invalid_input, "Body expects data in Array")
        }

        var answers = [];
        var user_id = req['currentUserId'];

        for (var i = 0; i < body.length; i++) {
            let payload = { question_id: body[i]['question_id'], question_answer: body[i]['question_answer'], user_id }
            const filter = { _id: body[i]['question_id'] }
            const isExist = await Question.isExist(filter);
            if (!isExist) continue;

            const isAnswered = await UserAnswers.get({ question_id: body[i]['question_id'], user_id })
            const [question] = await Question.get(filter);
            if (isAnswered.length > 0 && question.question_type == QUESTION_TYPES.SPLASH_QUESTION) {
                continue;
            };

            const answer = await UserAnswers.add(payload);
            answers.push(answer);
            logger.log(level.info, `createSplashScreenAnswer Answer Created: ${beautify(answer)}`);
        }

        User.update({ _id: user_id }, { is_splash_answered: true });

        return okResponse(res, messages.created.replace("{dynamic}", "Answer"), answers);

    } catch (error) {
        logger.log(level.error, `createSplashScreenAnswer Error: ${beautify(error.message)}`);
        return internalServerError(res, error)
    }
}