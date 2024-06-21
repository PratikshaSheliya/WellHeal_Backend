import logger, { level } from "../../config/logger.js";
import { beautify } from "../utils/utility.js";
export const getAllSubscriptionAutoEndUserDetails = async (req,res) => {
    logger.log(level.info, `Pipeline getAllSubscriptionAutoEndUserDetails`);
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
            is_plan_running: true,
            is_plan_cancel:true,
            _id: { $exists: true },
            // $or: [
            //   { "getAllTrialUserinfo.is_deleted": { $ne: false } }
            // ],
            $or: [
              { "getAllTrialUserinfo.current_phase.is_schedule": { $ne: false } }
            ],
            $or: [
              { "getAllTrialUserinfo.current_phase.startDate": { $ne: null } }
            ],
            $or: [
              { "getAllTrialUserinfo.current_phase.endDate": { $ne: null } }
            ],
            $or: [
              { "getAllTrialUserinfo.current_phase.trialEnd": { $ne: null } }
            ],
            $or: [
              { "getAllTrialUserinfo.current_phase.activePlanEndDate": { $ne: null } }
            ],
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

            startDate: "$getAllTrialUserinfo.current_phase.startDate",
            endDate: "$getAllTrialUserinfo.current_phase.endDate",
            trialEnd: "$getAllTrialUserinfo.current_phase.trialEnd",
            activePlanEndDate: "$getAllTrialUserinfo.current_phase.activePlanEndDate",
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
    logger.log(level.info, `Pipeline getAllSubscriptionAutoEndUserDetails ${beautify(pipeline)}`);
    return { pipeline };
}

export const getAllSubscriptionAutoEndNonCancelUser = async (req,res) => {
    logger.log(level.info, `Pipeline getAllSubscriptionAutoEndNonCancelUser`);
    const pipeline = [
        {
            $lookup: {
              from: "payments",
              localField: "_id",
              foreignField: "user_id",
              as: "getAllSubscriptionUsers"
            }
        },
        {
            $unwind: {
              path: "$getAllSubscriptionUsers",
              preserveNullAndEmptyArrays: true
            }
        },
        {
          $match: {
            is_deleted: false,
            is_trial_running: false,
            is_plan_running: true,
            is_plan_cancel:false,
            _id: { $exists: true },
            $or: [
              { "getAllSubscriptionUsers.current_phase.is_schedule": { $ne: false } }
            ],
            $or: [
              { "getAllSubscriptionUsers.current_phase.startDate": { $ne: null } }
            ],
            $or: [
              { "getAllSubscriptionUsers.current_phase.endDate": { $ne: null } }
            ],
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

            startDate: "$getAllSubscriptionUsers.current_phase.startDate",
            endDate: "$getAllSubscriptionUsers.current_phase.endDate",
            subscribeScheduleId: "$getAllSubscriptionUsers.subscribeScheduleId",
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
    logger.log(level.info, `Pipeline getAllSubscriptionAutoEndNonCancelUser ${beautify(pipeline)}`);
    return { pipeline };
}
