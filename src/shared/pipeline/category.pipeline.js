import logger, { level } from "../../config/logger.js";
import { MODAL_ID } from "../constant/types.const.js";
import { beautify, getPaginationOptions } from "../utils/utility.js";

export const getSubcategoryByCategoryPipeline =async (filter, option = null, optionalFilter = null) => {
    logger.log(level.info, `Pipeline getSubcategoryByCategoryPipeline args=${beautify(filter)} option=${beautify(option)}`);
    const opArgs = getPaginationOptions(option);
    logger.log(level.debug, `opArgs=${beautify(opArgs)}`);
    const pipeline = [
        { $match: { ...filter } },
        {
            $lookup: {
                'from': 'categories',
                'localField': 'category_id',
                'foreignField': '_id',
                'as': 'category'
            }
        },
        { $unwind: { 'path': '$category', "preserveNullAndEmptyArrays": true } },
        {
            $set: {
                [MODAL_ID.SubCategory]: '$_id',
                [`category.${MODAL_ID.Category}`]: '$category._id'
            }
        },
        {
            $unset: ['_id', 'category._id']
        }
    ];
    const countPipeline = [...pipeline];
    pipeline.push(...opArgs);
    logger.log(level.info, `Pipeline getSubcategoryByCategoryPipeline ${beautify(pipeline)}`);
    return { pipeline, countPipeline };
}