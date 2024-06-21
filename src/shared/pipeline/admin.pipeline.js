import logger, { level } from "../../config/logger.js";
import { MODAL_ID } from "../constant/types.const.js";
import { beautify} from "../utils/utility.js";

/* export const getCountryWiseUserCount = async () => {
    logger.log(level.info, `Pipeline getCountryWiseUserCount`);
    const pipeline = [
        {
            $group: {
                _id: '$country',
                user_count: { $sum: 1 }
            }
        },
        { $set: { country: '$_id' } },
        { $unset: '_id' }
    ];
    logger.log(level.info, `Pipeline getCountryWiseUserCount ${beautify(pipeline)}`);
    return { pipeline };
} */
export const getCountryWiseUserCount = async () => {
    logger.log(level.info, `Pipeline getCountryWiseUserCount`);
    const pipeline = [
        {
            $match: {
                $and: [
                    { country: { $exists: true } },
                    { country: { $ne: null } },
                    { country: { $ne: "" } }
                ]
                
            }
        },
        {
            $group: {
                _id: '$country',
                user_count: { $sum: 1 }
            }
        },
        {
            $project: {
                _id: 0,
                country: "$_id",
                user_count: 1
            }
        }
    ];
    logger.log(level.info, `Pipeline getCountryWiseUserCount ${beautify(pipeline)}`);
    return { pipeline };
}