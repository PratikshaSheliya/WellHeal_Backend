import logger, { level } from "../../config/logger.js";
import { beautify, getPaginationOptions } from "../utils/utility.js";
import mongoose from 'mongoose';

export const getAllFreeTrialUserDetails = async (req,res) => {
    logger.log(level.info, `Pipeline getAllTrialUserDetails`);
      const pipeline = [
          {
            $match: {
              is_deleted: false,
              userTrial: true,
              _id: { $exists: true }
              
            }
          },
          {
            $lookup: {
              from: "trialusers",
              localField: "_id",
              foreignField: "user_id",
              as: "getAllTrialUserinfo"
            }
          },
          {
            $unwind: {
              path: "$getAllTrialUserinfo",
              preserveNullAndEmptyArrays: true
            }
          },
          {
            $project: {
              user_id: "$_id",
              name: 1,
              email: 1,
              dob: 1,
              gender: 1,
              created_at: 1,
              userTrial: 1,
              userTrial_id: "$getAllTrialUserinfo._id",
              startTrial: "$getAllTrialUserinfo.startTrial",
              endTrial: "$getAllTrialUserinfo.endTrial",
              _id: 0,
              id: 1
            }
          },
          {
            $group: {
              _id: 1,
              data: { $push: "$$ROOT" },
              totalCount: { $sum: 1 }
            }
          },
          {
            $project: {
              _id: 0,
              data: 1,
              totalCount: 1
            }
          },
          {
            $unwind: "$data"
          },
          {
            $replaceRoot: { newRoot: "$data" }
          }
        ];
    logger.log(level.info, `Pipeline getAllFreeTrialUserDetails ${beautify(pipeline)}`);
    return { pipeline };
}