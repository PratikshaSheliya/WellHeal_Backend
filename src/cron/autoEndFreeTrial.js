import { logger, level } from "../config/logger.js";
import { beautify, internalServerError, badRequestError, okResponse, toObjectId, generateRandomString, paramMissingError, SendEmail, parseSearchOptions } from "../shared/utils/utility.js";
import moment from 'moment';
import { schedule } from 'node-cron';
import User from "../models/user.model.js";
import { getAllFreeTrialUserDetails } from "../shared/pipeline/autoEndFreeTrialUser.pipeline.js";

export const autoEndFreeTrial = async () =>{

  const {pipeline} = await getAllFreeTrialUserDetails();

  const getAllTrialUserinfo = await User.aggregate(pipeline);

  logger.log(level.info, `getAllFreTrialUsers : ${beautify(getAllTrialUserinfo)}`);

      if( getAllTrialUserinfo.length >0 || getAllTrialUserinfo!=="" || getAllTrialUserinfo!==undefined ||getAllTrialUserinfo!==null){
        const currentDate = moment();
        await getAllTrialUserinfo.forEach(user => {

            const endTrialDate =  moment(user.endTrial);
            const userTrial = user.userTrial;

            if(endTrialDate !==null || endTrialDate !==undefined || endTrialDate !=="" && userTrial !==false || userTrial !==null ||userTrial !==undefined || userTrial !==""){
                
              if (endTrialDate.isSameOrBefore(currentDate, 'day')) {
                  autoEndUserFreTiralAction(user.user_id); 
                  }
                  else{
                    logger.log(level.info, `No cron will be run yet`); 
                  }
              }
        });
      }
      else{
        logger.log(level.info, `Now, No Users Having Free Trial  : ${beautify(getAllTrialUserinfo)}`);
      } 
}

  // Function to perform action when trial ends
  async function autoEndUserFreTiralAction(userId) {    

    logger.log(level.info, `Performing action for Free Users Trial User IDs: ${beautify(userId)}`);

    // Perform necessary action when the trial ends
    const endFreeUserTrial = await User.update({_id: userId}, {userTrial: false});
    
    if(!endFreeUserTrial){
        logger.log(level.info, `Free User Trial Is Expired and set it to be false`);
    }
    else{
      logger.log(level.info, `Now No User Exist Who Having Free Trial`);
    }

  }