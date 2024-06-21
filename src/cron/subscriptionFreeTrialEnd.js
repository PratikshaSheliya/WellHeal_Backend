import { logger, level } from "../config/logger.js";
import { beautify, internalServerError, badRequestError, okResponse, toObjectId, generateRandomString, paramMissingError, SendEmail, parseSearchOptions } from "../shared/utils/utility.js";
import moment from 'moment';
import User from "../models/user.model.js";
import { getAllSubscriptionFreeTrialUserDetails } from "../shared/pipeline/subscriptionFreeTrialEnd.pipeline.js";

export const subscriptionFreeTrialEnd = async () =>{

  const {pipeline} = await getAllSubscriptionFreeTrialUserDetails();

  const getAllSubscriptionFreeTrialUserinfo = await User.aggregate(pipeline);
  logger.log(level.info, `getAllSubscriptionFreeTrialUserinfo : ${beautify(getAllSubscriptionFreeTrialUserinfo)}`);

      if( getAllSubscriptionFreeTrialUserinfo.length >0){
        let currentDate = moment();
        await getAllSubscriptionFreeTrialUserinfo.forEach(user => {
            let endDate = user.trialEnd;
            let endTrialDate =  moment(endDate);

            let userId = user.user_id;


            if(endTrialDate !==null || endTrialDate !==undefined || endTrialDate !==""){
              if (currentDate.isAfter(endTrialDate)) {
                    subscriptionFreeTrialEndAction(userId); 
                  }
                  else{
                    logger.log(level.info, `No cron will be run yet`); 
                  }
              }
        });
      }
      else{
        logger.log(level.info, `Now, No Users Having Subscription Trial Running True  : ${beautify(getAllSubscriptionFreeTrialUserinfo)}`);
      } 
}

  // Function to perform action when trial ends By Automatically
  async function subscriptionFreeTrialEndAction(userId) {    

      logger.log(level.info, `Performing action for Subscription Trial IDs: ${beautify(userId)}`);

      // Perform necessary action when the trial ends
        const endFreeUserTrial = await User.update({_id: userId}, {is_trial_running: false,is_plan_running:true});
            if(!endFreeUserTrial){
                logger.log(level.info, `Error in Updating Subscription is_trial_running false Trial`);
            }
            else{
              logger.log(level.info, `Now User Subscription Trial is End And Plan is Running Now${endFreeUserTrial}`);
              logger.log(level.info, `Now No User Exist Who Having Subscription Trial And Plan is Running Now`);
            }

  }

  
