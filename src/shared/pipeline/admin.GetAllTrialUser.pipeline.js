import logger, { level } from "../../config/logger.js";
import { beautify, getPaginationOptions } from "../utils/utility.js";

export const getAllTrialUserDetails = async (filter, option = null, fromDateUtc=null, toDateUtc=null) => {
    //logger.log(level.info, `Pipeline getAllTrialUserDetails`);
    const opArgs = getPaginationOptions(option);

    let dateFilter = {};

    if (fromDateUtc && toDateUtc) {
        dateFilter = {
            created_at: {
                $gte: new Date(fromDateUtc),
                $lte: new Date(toDateUtc),
            }
        };
    }

    const pipeline = [
      {
          $match: {
            ...filter,
            ...dateFilter,
        },
        
      },
      {
          $lookup: {
          from: "trialusers",
          localField: "_id",
          foreignField: "user_id",
          as: "getAllTrialUserinfo",
          },
      },
      {
          $unwind: {
          path: "$getAllTrialUserinfo",
          preserveNullAndEmptyArrays: true,
          },
      },
      {
          $project: {
          //user_id: "$_id",
          name: 1,
          email: 1,
          phone_number: 1,
          social_id: 1,
        //   dob: 1,
        //   gender: 1,
          created_at: 1,
          userTrial: 1,
          
          userTrial_id: "$getAllTrialUserinfo._id",
          startTrial: "$getAllTrialUserinfo.startTrial",
          endTrial: "$getAllTrialUserinfo.endTrial",
          _id: 1, // Exclude _id field
          id: 1,  // Exclude id field
          },
      },
      {
          $group: {
          _id: 1,
          data: { $push: "$$ROOT" },
          },
      },
      {
          $project: {
          _id: 0,
          data: 1,
          },
      },
      {
          $unwind: "$data"
      },
      {
          $replaceRoot: { newRoot: "$data" }
      },
    ];
    const countPipeline = [...pipeline];
    pipeline.push(...opArgs);      
    return { pipeline,countPipeline };
}