import { logger, level } from "../config/logger.js";
import { beautify, internalServerError, badRequestError, okResponse, toObjectId, generateRandomString, paramMissingError, SendEmail, parseSearchOptions } from "../shared/utils/utility.js";
import moment from 'moment';
import User from "../models/user.model.js";
import Payment from "../models/payment.model.js";

import { getAllSubscriptionAutoEndUserDetails,getAllSubscriptionAutoEndNonCancelUser } from "../shared/pipeline/subscriptionAutoEnd.pipeline.js";

export const subscriptionPlanCancelByUserPlanAutoEnd = async () =>{

  const {pipeline} = await getAllSubscriptionAutoEndUserDetails();
  const getAllSubscriptionFreeTrialUserinfo = await User.aggregate(pipeline);
  //logger.log(level.info, `getAllSubscriptionFreeTrialUserinfo : ${beautify(getAllSubscriptionFreeTrialUserinfo)}`);

      if( getAllSubscriptionFreeTrialUserinfo.length >0){
        let currentDate = moment();

        await getAllSubscriptionFreeTrialUserinfo.forEach(user => {
            
            let planActiveEndDate = user.activePlanEndDate;
            // let activePlanEndDate =  moment("2023-09-14T19:26:24+05:30");
            //let activePlanEndDate =  moment("2023-09-14T18:39:22Z");
            let activePlanEndDate =  moment(planActiveEndDate);

            let userId = user.user_id;

            if(activePlanEndDate !==null || activePlanEndDate !==undefined || activePlanEndDate !=="" ){
              if (currentDate.isAfter(activePlanEndDate)) {
                    subscriptionAutoEndAction(userId); 
                  }
                  else{
                    logger.log(level.info, `No cron will be run yet`); 
                  }
              }
        });
      }
      else{
        logger.log(level.info, `Now, No Users Having Subscription Auto End By User Plan Cancelled   : ${beautify(getAllSubscriptionFreeTrialUserinfo)}`);
      } 
}


export const subscriptionAutoEndNonCancel = async () =>{

  const {pipeline} = await getAllSubscriptionAutoEndNonCancelUser();
  const getAllSubscriptionPlanEndUserinfo = await User.aggregate(pipeline);

  //logger.log(level.info, `getAllSubscriptionPlanEndUserinfo : ${beautify(getAllSubscriptionPlanEndUserinfo)}`);

      if( getAllSubscriptionPlanEndUserinfo.length >0){
        let currentDate = moment();
        await getAllSubscriptionPlanEndUserinfo.forEach(user => {
            
            let plan_EndDate = user.endDate;
           let planEndDate =  moment(plan_EndDate);
            // let planEndDate =  moment("2023-09-14T18:39:22Z");

            let userId = user.user_id;

            if(planEndDate !==null || planEndDate !==undefined || planEndDate !=="" ){
              if (currentDate.isAfter(planEndDate)) {
                    subscriptionAutoEndNonCancelAction(userId); 
                  }
                  else{
                    logger.log(level.info, `No cron will be run yet`); 
                  }
              }
        });
      }
      else{
        logger.log(level.info, `Now, No Users Having Final Subscription Paln Auto End   : ${beautify(getAllSubscriptionPlanEndUserinfo)}`);
      } 
}

  // Function to perform action when trial ends
  async function subscriptionAutoEndAction(userId) {    
    logger.log(level.info, `Performing action for Subscription Trial IDs: ${beautify(userId)}`);
    // Perform necessary action when the trial ends
    const autoEndSubscription = await User.update({_id: userId}, {is_plan_running:false, is_plan_cancel: false});
        if(!autoEndSubscription){
            logger.log(level.info, `Error in Updating Subscription is_plan_running false Trial`);
        }
        else{
            //HARD DELETED CODE
            const paymentDeleted= await Payment.deleteMany({ user_id: userId });
            if(paymentDeleted){
            logger.log(level.info, `Subscription is_plan_running && is_plan_cancel Now updated with flase Updated Sucessfully`);

              logger.log(level.info, `Subscription Deleted Due To Plan End ${userId} DELTED ==> ${paymentDeleted}`);
              logger.log(level.info, `Now No User Exist Who Having Subscription Plan is Running Now`);
            }
            else{
              logger.log(level.info, `Error in Subscription Plan is not deleted yet`);

            }
            //SOFT DELETED CODE
            /* const paymentSoftDeleted =  await Payment.update({ user_id: userId,is_schedule:true,is_schedule:false},{is_deleted:true});
            if(paymentSoftDeleted){
              logger.log(level.info, `Now No User Exist Who Having Subscription Plan is Running Now and its soft deleted`);
            }
            else{
              logger.log(level.info, `Error in Subscription Plan is not deleted yet`);

            } */
        }

        
  }

  // Function to perform action when subscription plan ends by its self without user cancel at the end of the plan
  async function subscriptionAutoEndNonCancelAction(userId) {    
    logger.log(level.info, `Performing action for Final Subscription Auto End User IDs: ${beautify(userId)}`);
    // Perform necessary action when the trial ends
    const autoEndSubscription = await User.update({_id: userId}, {is_plan_running:false, is_plan_cancel: false,is_schedule:false});
        if(!autoEndSubscription){
            logger.log(level.info, `Error in Updating Final Subscription is_plan_running false Trial`);
        }
        else{
            logger.log(level.info, `Final Subscription is_plan_running && is_plan_cancel Now updated with flase Updated Sucessfully`);

            const paymentDeleted= await Payment.deleteMany({ user_id: userId });
            logger.log(level.info, `Final Subscription Delted Due To Plan End ${userId} DELTED ==> ${paymentDeleted}`);
            logger.log(level.info, `Now No User Exist Who Having Final Subscription Plan is Running Now`);
            
            /* //SOFT DELETED CODE
            const paymentDeleted =  await Payment.update({ user_id: userId,is_schedule:true,is_schedule:false},{is_deleted:true});
            if(paymentDeleted){
              console.log("paymentDeleted::::::::",paymentDeleted);
              logger.log(level.info, `Final Subscription Soft Deleted Due To Plan End ${userId} DELTED ==> ${paymentDeleted}`);
              logger.log(level.info, `Now No User Exist Who Having Final Subscription Plan is Running Now`);
            }
            else{
            logger.log(level.info, `Error in Updating Final Subscription Soft Deleted is_plan_running false Trial`);

            } */
          }
  }

  
