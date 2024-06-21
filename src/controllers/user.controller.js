import Stripe from "stripe";
import messages from "../shared/constant/messages.const.js";
import { logger, level } from "../config/logger.js";
import Favorites from "../models/favorite.model.js";
import Therapy from "../models/therapy.model.js";
import { internalServerError, beautify, okResponse, generateRandomString, badRequestError, toObjectId, paramMissingError } from "../shared/utils/utility.js";
import { AUDIO_VIDEO_EXTENSIONS, DOC_EXTENSIONS, FAVORITE_CONTENT_TYPE, IMAGE_EXTENSIONS, SLUG_TYPE } from "../shared/constant/types.const.js";
import Slug from "../models/slugs.model.js";
import { getSignedUrl, uploadFileToS3 } from "../shared/services/file-upload/aws-s3.service.js";
import Path from "path";
import Resource from "../models/resource.model.js";
import User from "../models/user.model.js";
import { returnOnNotExist } from "../shared/services/database/query.service.js";
import { getProgressOfTherapies } from "../shared/pipeline/therapy.pipeline.js";
import UserProgress from "../models/user_progress.model.js";
import UserToken from "../models/user_token.model.js";
import { sendPushNotification } from "../shared/services/firebase/send_notification.service.js";
import ReviewRating from "../models/review_rating.model.js";
import Notification from "../models/notification.model.js";
import scheduleNotification from "../models/schedule_notification.model.js";
import UserDevices from "../models/user_devices_model.js";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

export const getFavouriteTherapies = async (req, res) => {
  try {
    const { query } = req;
    const { type = FAVORITE_CONTENT_TYPE.THERAPY, option = {} } = query;

    logger.log(level.info, `getFavouriteTherapies`);

    const filter = { user_id: req['currentUserId'], content_type: type };

    const favouriteTherapyIds = (await Favorites.get(filter, null, option)).map(elem => elem["favourite_id"]);
    const count = await Favorites.count(filter);

    let modelName = Therapy;
    switch (Number(type)) {
      case FAVORITE_CONTENT_TYPE.THERAPY:
        modelName = Therapy;
        break;
      case FAVORITE_CONTENT_TYPE.RESOURCE:
        modelName = Resource;
        break;
    }

    var records = await modelName.get({ _id: { $in: favouriteTherapyIds }, is_deleted: false });

    if (type == FAVORITE_CONTENT_TYPE.THERAPY) {
      let therapy_ids = records.map(item => item._id)
      const filter = { user_id: toObjectId(req['currentUserId']), therapy_id: { $in: [...therapy_ids] } };
      let progressPipeline = await getProgressOfTherapies(filter)
      const progress = await UserProgress.aggregate(progressPipeline);
      let ratings = await ReviewRating.get(filter);
      records = await integrateProgressWithTherapy(progress, records, ratings);
    }

    return okResponse(res, messages.record_fetched, records, count);
  } catch (error) {
    logger.log(level.error, `getFavouriteTherapies Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
}

export const submitHelpAndFeedback = async (req, res) => {
  try {
    const { body, file } = req;
    const { title, description } = body;

    const slugS3Folder = process.env.Aws_Upload_Path_For_Slug;
    const fileName = generateRandomString();
    let filePath;

    if (file) {
      filePath = Path.parse(file.originalname);

      if (!(Object.values({ ...IMAGE_EXTENSIONS, ...AUDIO_VIDEO_EXTENSIONS, ...DOC_EXTENSIONS }).includes(filePath.ext))) {
        logger.log(level.info, 'submitHelpAndFeedback invalid file selection error')
        return badRequestError(res, messages.invalid_file_selected);
      }
    }

    logger.log(level.info, `submitHelpAndFeedback body=${beautify(body)}`);

    const feedback = await Slug.add({ title, description, content_type: SLUG_TYPE.HELP_FEEDBACK, user_id: req['currentUserId'] });
    if (!feedback) {
      logger.log(level.info, `submitHelpAndFeedback Error`)
      return badRequestError(res, messages.invalid_input);
    }

    if (file) {

      const s3Location = `${slugS3Folder}thumbnail/${fileName}${filePath.ext}`;
      uploadFileToS3(process.env.Aws_Bucket_Name, s3Location, file).then((result, error) => {
        if (!error) {
          Slug.update({ _id: feedback._id }, { url: s3Location });
        } else {
          logger.log(level.error, `submitHelpAndFeedback Error : Thumbnail upload : ${beautify(error)}`);
        }
      });
      feedback['url'] = await getSignedUrl(process.env.Aws_Bucket_Name, s3Location);
    }

    logger.log(level.info, `submitHelpAndFeedback content=${beautify(feedback)}`);
    return okResponse(res, messages.created.replace("{dynamic}", "Therapy"), feedback);

  } catch (error) {
    logger.log(level.error, `submitHelpAndFeedback Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
}

export const removeAccount = async (req, res) => {
  try {
    const deletedCondition = { $or: [{ is_deleted: false }, { is_deleted: { $exists: false } }] }
    const filter = { _id: req['currentUserId'], ...deletedCondition };
    const notExist = await returnOnNotExist(User, filter, res, "User", messages.not_exist.replace("{dynamic}", "User"));
    if (notExist) return;

    const user = await User.update(filter, { is_deleted: true, deleted_at: new Date().toISOString() });
    const userData = await User.get({_id: req['currentUserId']});
    if(userData[0]?.customer_id){
      const deleteAccount = await stripe.customers.del(userData[0]?.customer_id);
      logger.log(level.info, `delete Account in stripe body=${beautify(deleteAccount)}`);
    }
    return okResponse(res, messages.deleted.replace("{dynamic}", "User"), user);
  }
  catch (error) {
    logger.log(level.error, `removeAccount Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
}

export const sendNotificationToUser = async (req, res) => {
  try {
    const {body, file} = req;
    const {users = [], title = "Notifications", message, isSchedule, schedule_time} = body;

    console.log("body ==> ", body)

    logger.log(level.info, `sendNotificationToUser body=${beautify(body)}`);

    if (users.length <= 0) {
      logger.log(level.error, `sendNotificationToUser error: Invalid Length of Users in a body`);
      return paramMissingError(res, messages.missing_key.replace("{dynamic}", "User"));
    }
    let imageUrl = "";
    let s3Location = "";
    if(file){
      const s3Folder = process.env.Aws_Upload_Path_For_Notification;
      const filePath = Path.parse(file.originalname);
      const fileName = generateRandomString();

      if (!(Object.values(IMAGE_EXTENSIONS).includes(filePath.ext))) {
        logger.log(level.info, 'sendNotificationToUser invalid file selection error')
        return badRequestError(res, messages.invalid_file_selected);
      }

      s3Location = `${s3Folder}thumbnail/${fileName}${filePath.ext}`;
      uploadFileToS3(process.env.Aws_Bucket_Name, s3Location, file).then(async (result, error) => {
        if (error) {
          logger.log(level.error, `sendNotificationToUser Error : Thumbnail upload : ${beautify(error)}`);
        }
      });
      imageUrl = await getSignedUrl(process.env.Aws_Bucket_Name, s3Location);
    }
    if (isSchedule === "true") {
      if (!schedule_time) {
        logger.log(level.info, 'send notification schedule_time found error')
        return paramMissingError(res, messages.missing_key.replace("{dynamic}", "schedule_time"));
      }
      const schNotification = await scheduleNotification.add({
        user_ids: [...users],
        title,
        description: message,
        image: s3Location,
        schedule_time,
        isSchedule,
        isSend: false
      });
      return okResponse(res, messages.schedule_create, schNotification);
    } else {
      console.log("caleeddddd");
      const userTokens = await UserToken.get({user_id: {$in: [...users]}, is_loggedOut: false});
      console.log("userTokens", userTokens)
      if (userTokens.length) {
        const deviceTokens = userTokens.map(token => token.device_token);
        logger.log(level.info, `sendNotificationToUser notification Tokens = ${beautify(deviceTokens)}`);
        const payload = {
          notification: {
            title: title,
            body: message,
            image: imageUrl || ""
          }
        };
        const result = await sendPushNotification(deviceTokens, payload, "high");
        var notification;
        if (result) {
          notification = await Notification.add({
            user_ids: [...users],
            title,
            description: message,
            image: imageUrl || "",
            schedule_time: null
          });
        }
        return okResponse(res, messages.notification_sent, notification);
      } else {
        return okResponse(res, messages.notification_sent);
      }
    }
  } catch (error) {
    logger.log(level.error, `sendNotificationToUser Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
};

function integrateProgressWithTherapy(progress = [], therapies = [], ratings = []) {
  let object = {}, ratingObject = {};
  progress.forEach(therapy => {
    object[therapy.therapy_id] = therapy.completed;
    ratingObject[therapy.therapy_id] = therapy.is_review_submitted;
  })
  ratings.forEach(therapy => {
    ratingObject[therapy.therapy_id] = true;
  })
  logger.log(level.info, `integrateProgressWithTherapy progresses:${beautify(object)}`);
  therapies = JSON.parse(JSON.stringify(therapies));

  therapies = therapies.map(therapy => {
    therapy['completed'] = object[therapy.therapy_id] || 0;
    therapy['is_review_submitted'] = ratingObject[therapy.therapy_id] || false;
    return therapy
  });
  return therapies;
}

export const deepLinking = async (req, res) => {
  try{
      const deepLink = {
        fallback: 'https://wellheal.app/',
        android_package_name: 'com.app.wellheal',
        ios_store_link:
          'https://apps.apple.com/in/app/apple-store/id1661262276'
      };
      return okResponse(res, "Deep link detail",  deepLink);
  }catch(error){
    logger.log(level.error, `sendNotificationToUser Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
}

export const deviceidExists = async (req, res) => {
  try{
    const { query } = req;
    const { device_id } = query;
    let deviceidExists;

    if(!device_id){
      return paramMissingError(res, messages.missing_key.replace("{dynamic}", "device_id"));
    }

    const userDevicesIdData = await UserDevices.get({device_id:device_id});
   
    if(userDevicesIdData.length>0){
        deviceidExists = Boolean(true)
        return okResponse(res, messages.deviceid_exist, {is_exists:deviceidExists});
    }
    else{
      deviceidExists = Boolean(false)
      await UserDevices.add({ device_id:device_id });
      return okResponse(res,messages.created.replace('{dynamic}', 'DeviceId'),{is_exists:deviceidExists});
    }
  }catch(error){
    logger.log(level.error, `Devices Data Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
}
