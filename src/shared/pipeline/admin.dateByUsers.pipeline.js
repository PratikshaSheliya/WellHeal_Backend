import logger, { level } from "../../config/logger.js";
import { beautify} from "../utils/utility.js";

export const getRegisterDateWiseUserCount = async (fromDateUtc,toDateUtc) => {
    logger.log(level.info, `Pipeline getRegisterDateWiseUserCount`);
    const pipeline = [
        {
            $match: {
                created_at: {
                    
                    $gte: new Date(fromDateUtc),
                    $lte: new Date(toDateUtc),
                }
                ,is_deleted: false ,is_verified:true
            }
        },
        {
            $group: {
                _id: null,
                user_count: { $sum: 1 }
            }
        },
        {
            $project: {
                _id: 0,
                user_count: 1
            }
        }
    ]
    logger.log(level.info, `Pipeline getRegisterDateWiseUserCount ${beautify(pipeline)}`);
    return { pipeline };
}