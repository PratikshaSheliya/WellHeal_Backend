import logger, { level } from "../../config/logger.js";
import { beautify, getPaginationOptions } from "../utils/utility.js";

export const getAllTherapyList = async (filter,option = null,searchFilter) => {

    const opArgs = getPaginationOptions(option);
    logger.log(level.debug, `opArgs=${beautify(opArgs)}`);

    const pipeline = [
        {
            $match: {...filter}
        },
        {
            $lookup: {
            from: "therapies",
            localField: "therapy_id",
            foreignField: "_id",
            as: "therapy",
            },
        },
        {
            $unwind: {
            path: "$therapy",
            preserveNullAndEmptyArrays: true,
            },
        },
        {
            $lookup: {
            from: "subcategories",
            localField: "sub_category_id",
            foreignField: "_id",
            as: "subcategory",
            },
        },
        {
            $unwind: {
            path: "$subcategory",
            preserveNullAndEmptyArrays: true,
            },
        },
        {
            $match: { 
             ...searchFilter 
            }      
        },
        {
            $project: {
                therapy_id: 1,
                sub_category_id: 1,
                subcategorytherapy_id: "$_id",
                is_deleted: 1,
                deleted_at:1,
                created_at :1,
                updated_at: 1,
                __v: 1,
                therapy: {  
                    $mergeObjects: [
                      "$therapy",
                        {
                            therapy_id: "$therapy._id",          
                        }
                    ]
                },
                sub_category: {
                    $mergeObjects: [
                        "$subcategory",
                        {
                            subcategory_id: "$subcategory._id",
                        }
                    ]
                },
                _id: 0,
                id: 1,
            },
        },
        
      ];
    
    const countPipeline = [...pipeline];
    pipeline.push(...opArgs);
           
    //logger.log(level.info, `Pipeline getAllTherapyList ${beautify(pipeline)}`);
    return { pipeline,countPipeline };
}