import logger, { level } from "../../config/logger.js";
import { beautify } from "../utils/utility.js";
export const getAllSubscriptionFreeTrialUserDetails = async (req,res) => {
    logger.log(level.info, `Pipeline getAllSubscriptionFreeTrialUserDetails`);
    const pipeline = [
        {
            $lookup: {
              from: "payments",
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
          $match: {
            is_deleted: false,
            is_trial_running: true,
            is_trial_cancel:false,
            is_plan_running: false,
            is_plan_cancel:false,
            _id: { $exists: true },
            // $or: [
            //   { "getAllTrialUserinfo.is_deleted": { $ne: false } }
            // ],
            $or: [
              { "getAllTrialUserinfo.is_schedule": { $ne: false } }
            ]
          }
        },

        {
          $project: {
            user_id: "$_id",
            name: 1,
            email: 1,
            phone: 1,
            is_trial_running: 1,
            is_trial_cancel: 1,
            is_plan_running: 1,
            is_plan_cancel: 1,

            userTrial_id: "$getAllTrialUserinfo._id",
            startDate: "$getAllTrialUserinfo.current_phase.startDate",
            endDate: "$getAllTrialUserinfo.current_phase.endDate",
            trialEnd: "$getAllTrialUserinfo.current_phase.trialEnd",
            subscribeScheduleId: "$getAllTrialUserinfo.subscribeScheduleId",
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
    logger.log(level.info, `Pipeline getAllSubscriptionFreeTrialUserDetails ${beautify(pipeline)}`);
    return { pipeline };
}