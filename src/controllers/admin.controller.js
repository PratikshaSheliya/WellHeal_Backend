import moment from "moment";
import { logger, level } from "../config/logger.js";
import Path from "path";
import JWTAuth from "../shared/services/jwt_auth/jwt_auth.service.js";
import pkg from "lodash";
import { beautify, internalServerError, badRequestError, okResponse, toObjectId, generateRandomString, paramMissingError, SendEmail, parseSearchOptions, decrypt } from "../shared/utils/utility.js";
import AdminUser from "../models/admin-user.model.js";
import messages from "../shared/constant/messages.const.js";
import User from "../models/user.model.js";
import { IMAGE_EXTENSIONS, SLUG_TYPE, VIDEO_EXTENSIONS, SLUG_RESOURCE_FORMAT } from "../shared/constant/types.const.js";
import Slug from "../models/slugs.model.js";
import { returnOnExist, returnOnNotExist } from "../shared/services/database/query.service.js";
import SubCategory from "../models/sub_category.model.js";
import Therapy from "../models/therapy.model.js";
import Resource from "../models/resource.model.js";
import TherapyResources from "../models/therapy_resources.model.js";
import IntroVideos from "../models/intro_videos.model.js";
import { getAverageRatingByTherapyPipeline } from "../shared/pipeline/therapy.pipeline.js";
import { getSignedUrl, uploadFileToS3 } from "../shared/services/file-upload/aws-s3.service.js";
import { getTop10MostUsedResource } from "../shared/pipeline/resource.pipeline.js";
import UserProgress from "../models/user_progress.model.js";
import { getCountryWiseUserCount } from "../shared/pipeline/admin.pipeline.js";
import { UserReportHtml } from "../shared/utils/templates.js";
import puppeteer from "puppeteer";
import fs from 'fs';
import Notification from "../models/notification.model.js";
import scheduleNotification from "../models/schedule_notification.model.js";
import Appversion from "../models/app_version.model.js";
import TrialUsers from "../models/trialUser.model.js";
import { getAllTrialUserDetails } from "../shared/pipeline/admin.GetAllTrialUser.pipeline.js";
import { getRegisterDateWiseUserCount } from "../shared/pipeline/admin.dateByUsers.pipeline.js";

const { _ } = pkg;
const __dirname = Path.resolve();

const auth = new JWTAuth();

export const signUp = async (req, res) => {
  try {
    let data = req.body;
    logger.log(level.info, `AdminSignup : body=${beautify(data)}`);
    let newUser = {
      name: data.name,
      email: data.email,
      phone_number: data.phone_number,
      password: data.password,
      address: data.address,
      city: data.city,
      state: data.state,
      country: data.country,
      zipcode: data.zipcode,
    };
    AdminUser.add(newUser).then(async (resp) => {
      logger.log(level.info, `AdminSignup Added : response=${beautify(resp)}`);
      return okResponse(res, messages.admin_registered_success, resp);
    }, (error) => {
      logger.log(level.error, `AdminSignup Not Added : error=${beautify(error)}`);
      return badRequestError(res, messages.bad_request, error);
    });
  } catch (error) {
    logger.log(level.error, `Admin Signup : Internal Server Error : Error=${beautify(error.message)}`);
    return internalServerError(res, error);
  }
};

export const adminLogin = async (req, res) => {
  try {
    let data = req.body;
    logger.log(level.info, `AdminLogin body : ${beautify(data)}`);
    const filter = { email: data.email, password: data.password };
    let userDoc = await userExist(filter);
    if (userDoc.length > 0) {
      const accessToken = await auth.createAdminToken(data.email, userDoc[0]._id);
      return okResponse(res, messages.login_success, { access_token: accessToken })
    } else {
      return badRequestError(res, messages.admin_missing, null)
    }
  } catch (error) {
    logger.log(level.error, `AdminLogin Error : ${beautify(error.message)}`);
    return internalServerError(res, error)
  }

};

export const getAllUsers = async (req, res) => {
  try {
    const { query } = req;
    let { option = {} ,fromDate=null,toDate=null, is_deleted, is_verified  } = query;
    const { sort = { created_at: -1 } } = option;
    let fromDateUtc, toDateUtc, specificStartDate, specificEndDate, userfilter;
    option['sort'] = sort;
   
    const currentDate = moment();
    if(fromDate !==null && toDate !==null ){
      specificStartDate = moment.utc(fromDate, 'YYYY-MM-DD');
      specificEndDate = moment.utc(toDate, 'YYYY-MM-DD');

      if(specificStartDate.isSameOrBefore(currentDate, 'day') && specificEndDate.isSameOrBefore(currentDate)){
        const formattedToDate = moment(toDate).endOf('day').toDate();
        fromDateUtc = new Date(fromDate).toISOString();
        toDateUtc =  formattedToDate.toISOString();
        }
        else{
          logger.log(level.info, `getAnalytics  From Date could not be greater than the Current date. =${fromDateUtc}`);
          return badRequestError(res, messages.invalid_key.replace("{dynamic}", `From Date or To Date could not be greater than the Current date.`));
        }
    }

    if(is_verified!==undefined && is_deleted !==undefined){
    userfilter = { is_deleted:  JSON.parse(is_deleted) ,is_verified: JSON.parse(is_verified)}
    }

    const searchFilter = await parseSearchOptions(option);
    const filter = {...userfilter, ...searchFilter};
    const {pipeline} = await getAllTrialUserDetails(filter,option, fromDateUtc, toDateUtc);
    const getAllTrialUserinfo = await User.aggregate(pipeline);
    let count = await getAllTrialUserinfo.length;

      getAllTrialUserinfo.forEach((user) => {
        user.email = decrypt(user.email);
      });
    
    //logger.log(level.info, `Admin getAllTrialUserinfo=${beautify(getAllTrialUserinfo)}`);
    
    return okResponse(res, messages.record_fetched, {getAllTrialUserinfo},count);
  } catch (error) {
    logger.log(level.error, `Admin getAllUsers Error : ${beautify(error.message)}`);
    return internalServerError(res, error)
  }
}

export const createFAQContent = async (req, res) => {
  try {
    const { body } = req;
    logger.log(level.info, `createFAQContent body=${beautify(body)}`);
    if (!Array.isArray(body)) {
      return badRequestError(res, messages.invalid_input, "Body expects data in Array")
    }

    var answers = [];

    for (var i = 0; i < body.length; i++) {
      let payload = { content_type: SLUG_TYPE.FAQ, title: body[i]['title'], description: body[i]['description'] }
      const answer = await Slug.add(payload);
      answers.push(answer);
    }
    logger.log(level.info, `createFAQContent Created: ${beautify(answers)}`);

    return okResponse(res, messages.created.replace("{dynamic}", "FAQ"), answers);
  } catch (error) {
    logger.log(level.error, `Admin createFAQContent Error : ${beautify(error.message)}`);
    return internalServerError(res, error)
  }
}

export const updateFAQContent = async (req, res) => {
  try {
    const { params, body } = req;
    const { faqId } = params;
    const { title, description } = body;
    const filter = { _id: faqId, content_type: SLUG_TYPE.FAQ };

    // Preparing Payload to update in DB
    const payload = {};
    title ? payload['title'] = title : null;
    description ? payload['description'] = description : null;

    logger.log(level.info, `updateFAQContent faqId=${faqId} body=${beautify(body)}`);
    const updatedFAQ = await Slug.update(filter, payload);
    logger.log(level.info, `updateFAQContent updatedSlug=${beautify(updatedFAQ)}`)
    if (updatedFAQ) {
      return okResponse(res, messages.updated.replace("{dynamic}", "FAQ"), updatedFAQ);
    } else {
      logger.log(level.info, `updateFAQContent Error`)
      return badRequestError(res, messages.invalid_input);
    }
  } catch (error) {
    logger.log(level.error, `Admin createFAQContent Error : ${beautify(error.message)}`);
    return internalServerError(res, error)
  }
}

export const deleteFAQContent = async (req, res) => {
  try {
    const { params } = req;
    const { faqId } = params;

    logger.log(level.info, `deleteFAQContent params=${beautify(params)}`);
    const FAQ = await Slug.delete({ _id: faqId, content_type: SLUG_TYPE.FAQ });
    if (!FAQ) {
      logger.log(level.info, 'deleteFAQContent error')
      return badRequestError(res, messages.invalid_input);
    }
    logger.log(level.info, `deleteFAQContent faq=${beautify(FAQ)}`);
    return okResponse(res, messages.deleted.replace("{dynamic}", "Faq"));

  } catch (error) {
    logger.log(level.error, `deleteFAQContent Error: ${beautify(error.message)}`);
    return internalServerError(res, error)
  }
}

export const getFAQContent = async (req, res) => {
  try {
    const { query } = req;
    const { option = {} } = query;
    const { sort = { created_at: -1 } } = option;
    option['sort'] = sort;
    logger.log(level.info, `getFAQContent option=${beautify(option)}`);
    
    const searchfilter = await parseSearchOptions(option);
    const filter = { content_type: SLUG_TYPE.FAQ , ...searchfilter}

    const faq = await Slug.get(filter, null, option);
    const total = faq.length;
    logger.log(level.info, `faq = ${beautify(faq)}`);
    return okResponse(res, messages.record_fetched, faq, total);
  } catch (error) {
    logger.log(level.error, `getFAQContent Error: ${beautify(error.message)}`);
    return internalServerError(res, error)
  }
}

export const createPrivacyPolicy = async (req, res) => {
  try {
    const { body } = req;
    const { description, content_type = SLUG_TYPE.PRIVACY_POLICY } = body;
    logger.log(level.info, `createPrivacyPolicy body=${beautify(body)}`);

    const filter = { content_type };

    if (content_type != SLUG_TYPE.PRIVACY_POLICY && content_type != SLUG_TYPE.TERMS_CONDITION) {
      return badRequestError(res, messages.invalid_key.replace("{dynamic}", `Content Type Should be ${SLUG_TYPE.PRIVACY_POLICY} or ${SLUG_TYPE.TERMS_CONDITION}.`));
    }

    let word = content_type == SLUG_TYPE.PRIVACY_POLICY ? "Privacy Policy" : "Terms & Conditions";

    const isExist = await returnOnExist(Slug, filter, res, word, messages.already_exist.replace("{dynamic}", word))
    if (isExist) return;

    let payload = { content_type, description }
    const privacy = await Slug.add(payload);
    logger.log(level.info, `createPrivacyPolicy Created: ${beautify(privacy)}`);

    return okResponse(res, messages.created.replace("{dynamic}", word), privacy);
  } catch (error) {
    logger.log(level.error, `Admin createPrivacyPolicy Error : ${beautify(error.message)}`);
    return internalServerError(res, error)
  }
}

export const updatePrivacyPolicy = async (req, res) => {
  try {
    const { params, body } = req;
    const { recordId, content_type = SLUG_TYPE.PRIVACY_POLICY } = params;
    const { description } = body;
    const filter = { _id: recordId, content_type };

    if (content_type != SLUG_TYPE.PRIVACY_POLICY && content_type != SLUG_TYPE.TERMS_CONDITION) {
      return badRequestError(res, messages.invalid_key.replace("{dynamic}", `Content Type Should be ${SLUG_TYPE.PRIVACY_POLICY} or ${SLUG_TYPE.TERMS_CONDITION}.`));
    }
    // Preparing Payload to update in DB
    const payload = {};
    description ? payload['description'] = description : null;

    let word = content_type == SLUG_TYPE.PRIVACY_POLICY ? "Privacy Policy" : "Terms & Conditions";

    logger.log(level.info, `updatePrivacyPolicy recordId=${recordId} body=${beautify(body)}`);
    const updatedPolicy = await Slug.update(filter, payload);
    logger.log(level.info, `updatePrivacyPolicy updatedSlug=${beautify(updatedPolicy)}`)
    if (updatedPolicy) {
      return okResponse(res, messages.updated.replace("{dynamic}", word), updatedPolicy);
    } else {
      logger.log(level.info, `updatePrivacyPolicy Error`)
      return badRequestError(res, messages.invalid_input);
    }
  } catch (error) {
    logger.log(level.error, `Admin updatePrivacyPolicy Error : ${beautify(error.message)}`);
    return internalServerError(res, error)
  }
}

export const deletePrivacyPolicy = async (req, res) => {
  try {
    const { params } = req;
    const { recordId, content_type = SLUG_TYPE.PRIVACY_POLICY } = params;

    logger.log(level.info, `deletePrivacyPolicy params=${beautify(params)}`);

    if (content_type != SLUG_TYPE.PRIVACY_POLICY && content_type != SLUG_TYPE.TERMS_CONDITION) {
      return badRequestError(res, messages.invalid_key.replace("{dynamic}", `Content Type Should be ${SLUG_TYPE.PRIVACY_POLICY} or ${SLUG_TYPE.TERMS_CONDITION}.`));
    }

    const policy = await Slug.delete({ _id: recordId, content_type });
    if (!policy) {
      logger.log(level.info, 'deletePrivacyPolicy error')
      return badRequestError(res, messages.invalid_input);
    }
    logger.log(level.info, `deletePrivacyPolicy policy=${beautify(policy)}`);
    let word = content_type == SLUG_TYPE.PRIVACY_POLICY ? "Privacy Policy" : "Terms & Conditions";
    return okResponse(res, messages.deleted.replace("{dynamic}", word));

  } catch (error) {
    logger.log(level.error, `deletePrivacyPolicy Error: ${beautify(error.message)}`);
    return internalServerError(res, error)
  }
}

export const getPrivacyPolicy = async (req, res) => {
  try {
    const { params } = req;
    const { content_type } = params;

    logger.log(level.info, `getPrivacyPolicy content_type=${content_type}`);

    if (content_type && content_type != SLUG_TYPE.PRIVACY_POLICY && content_type != SLUG_TYPE.TERMS_CONDITION) {
      return badRequestError(res, messages.invalid_key.replace("{dynamic}", `Content Type Should be ${SLUG_TYPE.PRIVACY_POLICY} or ${SLUG_TYPE.TERMS_CONDITION}.`));
    }

    let filter;

    if (content_type) {
      filter = { content_type }
    } else {
      filter = {
        $or: [{ content_type: SLUG_TYPE.PRIVACY_POLICY }, { content_type: SLUG_TYPE.TERMS_CONDITION }]
      }
    }
    const policy = await Slug.get(filter);
    logger.log(level.info, `policy = ${beautify(policy)}`);
    return okResponse(res, messages.record_fetched, content_type ? (policy.length > 0 ? policy[0] : {}) : policy);
  } catch (error) {
    logger.log(level.error, `getPrivacyPolicy Error: ${beautify(error.message)}`);
    return internalServerError(res, error)
  }
}

export const getAnalytics = async (req, res) => {
  try {
    const { query } = req;
    let { most_viewed_resource = 10,fromDate=null,toDate=null } = query;
    logger.log(level.info, `getAnalytics query=${beautify(query)}`);

    let fromDateUtc, toDateUtc, specificStartDate, specificEndDate;
    const currentDate = moment();
    if(fromDate !==null && toDate !==null ){
      
      specificStartDate = moment.utc(fromDate, 'YYYY-MM-DD');
      specificEndDate = moment.utc(toDate, 'YYYY-MM-DD');

      if(specificStartDate.isSameOrBefore(currentDate, 'day') && specificEndDate.isSameOrBefore(currentDate)){
        const formattedToDate = moment(toDate).endOf('day').toDate();
        fromDateUtc = new Date(fromDate).toISOString();
        toDateUtc =  formattedToDate.toISOString();
        }
        else{
          logger.log(level.info, `getAnalytics  From Date could not be greater than the Current date. =${fromDateUtc}`);
          return badRequestError(res, messages.invalid_key.replace("{dynamic}", `From Date or To Date could not be greater than the Current date.`));
        }
    }
     

    const deletedFalse ={is_deleted: false}
    const activeUserFilter = { is_verified: true,is_deleted: false }
    const inActiveUserFilter = { is_verified: false }
    const isDeletedUserFilter = { is_deleted: true }
    const totalUsers = await User.count();
    const activeUsers = await User.count(activeUserFilter);
    const InActiveUsers = await User.count(inActiveUserFilter);
    const deletedUsers = await User.count(isDeletedUserFilter);
    const totalSubCategories = await SubCategory.count(deletedFalse);
    const totalTherapies = await Therapy.count(deletedFalse);
    const totalResources = await Resource.count(deletedFalse);
    const totalTherapyResources = await TherapyResources.count(deletedFalse);
    const totalIntroVideos = await IntroVideos.count(deletedFalse);
    const totalFaq = await Slug.count({ content_type: SLUG_TYPE.FAQ });
    const { pipeline } = await getTop10MostUsedResource({ limit: most_viewed_resource, sort: { 'total_view': -1 } });
    const mostViewedResources = await UserProgress.aggregate(pipeline);
    const { pipeline: countryPipeline } = await getCountryWiseUserCount();
    const countryWiseUserCount = await User.aggregate(countryPipeline);
    const { pipeline: dateByUserPipeline } = await getRegisterDateWiseUserCount(fromDateUtc,toDateUtc);
    const dateWiseUserCount = await User.aggregate(dateByUserPipeline);
    let dateByUserCount;
    
    if(dateWiseUserCount.length > 0){
      dateByUserCount =dateWiseUserCount;
    }
    else{
      dateByUserCount="Users Not Found";
    }

    const data = {
      totalUsers,
      activeUsers,
      InActiveUsers,
      deletedUsers,
      totalSubCategories,
      totalTherapies,
      totalResources,
      totalTherapyResources,
      totalIntroVideos,
      totalFaq,
      mostViewedResources,
      countryWiseUserCount,
      dateByUserCount
    }
    return okResponse(res, messages.record_fetched, data);

  } catch (error) {
    logger.log(level.error, `getAnalytics Error: ${beautify(error.message)}`);
    return internalServerError(res, error)
  }
}

export const getAverageTherapyRating = async (req, res) => {
  try {
    const { query } = req;
    const { option = {} } = query;
    const { sort = { created_at: -1 } } = option;
    option['sort'] = sort;
    const searchFilter = await parseSearchOptions(option);
    const filter = { is_deleted: false,...searchFilter};

    logger.log(level.info, `getAverageTherapyRating option=${option}`);
    const pipeline = getAverageRatingByTherapyPipeline(filter, option);
    let therapy = await Therapy.aggregate(pipeline);
    let count = await therapy.length;
    return okResponse(res, messages.record_fetched, therapy, count);

  } catch (error) {
    logger.log(level.error, `getAnalytics Error: ${beautify(error.message)}`);
    return internalServerError(res, error)
  }
}

export const deleteUser =async(req,res)=>{
    try {
      
      const { params } = req;
      const { userId } = params;
      const deletedCondition = { $or: [{ is_deleted: false }, { is_deleted: { $exists: false } }] }
      const filter = { _id: userId, ...deletedCondition };
      const notExist = await returnOnNotExist(User, filter, res, "User", messages.not_exist.replace("{dynamic}", "User"));
      if (notExist) return;

      const user = await User.update(filter, { is_deleted: true, deleted_at: new Date().toISOString() });
      return okResponse(res, messages.deleted.replace("{dynamic}", "User"), user);
    } 
    catch (error) {
      logger.log(level.error, `User Delete Error: ${beautify(error.message)}`);
        return internalServerError(res, error)
    }

}

export const createSplashScreenContent = async (req, res) => {
  try {
    const { body, file } = req;
    const { description } = body;

    if (!file) {
      logger.log(level.info, 'createSplashScreenContent no file selection found error')
      return paramMissingError(res, messages.missing_key.replace("{dynamic}", "File"));
    }

    const slugS3Folder = process.env.Aws_Upload_Path_For_Slug;
    const filePath = Path.parse(file.originalname);
    const fileName = generateRandomString();

    if (!(Object.values(IMAGE_EXTENSIONS).includes(filePath.ext))) {
      logger.log(level.info, 'createSplashScreenContent invalid file selection error')
      return badRequestError(res, messages.invalid_file_selected);
    }

    logger.log(level.info, `createSplashScreenContent body=${beautify(body)}`);

    const splashContent = await Slug.add({ description, content_type: SLUG_TYPE.SPLASH_SCREEN });
    if (!splashContent) {
      logger.log(level.info, `createSplashScreenContent Error`)
      return badRequestError(res, messages.invalid_input);
    }

    const s3Location = `${slugS3Folder}thumbnail/${fileName}${filePath.ext}`;
    uploadFileToS3(process.env.Aws_Bucket_Name, s3Location, file).then((result, error) => {
      if (!error) {
        Slug.update({ _id: splashContent._id }, { url: s3Location });
      } else {
        logger.log(level.error, `createSplashScreenContent Error : Thumbnail upload : ${beautify(error)}`);
      }
    });

    splashContent['url'] = await getSignedUrl(process.env.Aws_Bucket_Name, s3Location);

    logger.log(level.info, `createSplashScreenContent content=${beautify(splashContent)}`);
    return okResponse(res, messages.created.replace("{dynamic}", "Therapy"), splashContent);

  } catch (error) {
    logger.log(level.error, `createSplashScreenContent Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
}

export const updateSplashScreenContent = async (req, res) => {
  try {
    const { body, file, params } = req;
    const { description } = body;
    const { splashContentId } = params;

    const isNotExist = await returnOnNotExist(Slug, { _id: splashContentId, content_type: SLUG_TYPE.SPLASH_SCREEN }, res, "Splash Screen Record", messages.not_exist.replace("{dynamic}", "Splash Screen Record"));
    if (isNotExist) return;

    let s3Location;
    if (file) {
      const slugS3Folder = process.env.Aws_Upload_Path_For_Slug;
      const filePath = Path.parse(file.originalname);
      const fileName = generateRandomString();
      s3Location = `${slugS3Folder}thumbnail/${fileName}${filePath.ext}`;

      if (!(Object.values(IMAGE_EXTENSIONS).includes(filePath.ext))) {
        logger.log(level.info, 'createSplashScreenContent invalid file selection error')
        return badRequestError(res, messages.invalid_file_selected);
      }
    }

    logger.log(level.info, `createSplashScreenContent body=${beautify(body)}`);
    var updatedContent;
    if (description) {
      updatedContent = await Slug.update({ _id: splashContentId, content_type: SLUG_TYPE.SPLASH_SCREEN }, { description });
    }

    if (file) {
      uploadFileToS3(process.env.Aws_Bucket_Name, s3Location, file).then((result, error) => {
        if (!error) {
          Slug.update({ _id: splashContentId, content_type: SLUG_TYPE.SPLASH_SCREEN }, { url: s3Location });
        } else {
          logger.log(level.error, `createSplashScreenContent Error : Thumbnail upload : ${beautify(error)}`);
        }
      });
      updatedContent['url'] = await getSignedUrl(process.env.Aws_Bucket_Name, s3Location);
    }

    logger.log(level.info, `createSplashScreenContent content=${beautify(updatedContent)}`);
    return okResponse(res, messages.updated.replace("{dynamic}", "Splash Content"), updatedContent);

  } catch (error) {
    logger.log(level.error, `createSplashScreenContent Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
}

export const deleteSplashScreenContent = async (req, res) => {
  try {
    const { params } = req;
    const { splashContentId } = params;

    logger.log(level.info, `deleteSplashScreenContent params=${beautify(params)}`);
    const Content = await Slug.delete({ _id: splashContentId, content_type: SLUG_TYPE.SPLASH_SCREEN });

    logger.log(level.info, `deleteSplashScreenContent content=${beautify(Content)}`);
    return okResponse(res, messages.deleted.replace("{dynamic}", "Content"));

  } catch (error) {
    logger.log(level.error, `deleteSplashScreenContent Error: ${beautify(error.message)}`);
    return internalServerError(res, error)
  }
}

export const getSplashScreenContent = async (req, res) => {
  try {
    const { query } = req;
    const { option = {} } = query;
    const { sort = { created_at: -1 } } = option;
    option['sort'] = sort;

    logger.log(level.info, `getSplashScreenContent option=${beautify(option)}`);

    const searchFilter = await parseSearchOptions(option);
    const filter = { content_type: SLUG_TYPE.SPLASH_SCREEN, ...searchFilter }
    const content = await Slug.get(filter, null, option);
    const total = await content.length;
    logger.log(level.info, `content = ${beautify(content)}`);
    return okResponse(res, messages.record_fetched, content, total);
  } catch (error) {
    logger.log(level.error, `getSplashScreenContent Error: ${beautify(error.message)}`);
    return internalServerError(res, error)
  }
}

async function userExist(filter) {
  let userDoc = await AdminUser.get(filter);
  return userDoc;
}

export const changeUserStatus = async (req, res) => {
  try {
    const { userId } = req.params;

    logger.log(level.info, `changeUserStatus Params=${req.params}`);

    const isExist = await returnOnNotExist(User, { _id: toObjectId(userId) });
    if (isExist) return;

    await User.update({ _id: toObjectId(userId) }, { status: 0 });

    return okResponse(res, messages.user_status_updated);
  } catch (error) {
    logger.log(level.error, `changeUserStatus Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
}

export const updateProfile = async (req, res) => {
  try {
    const { body } = req;
    const { name = null, address = null, city = null, state = null, country = null, zipcode = null } = body;

    const adminId = req['currentUserId'];
    const payload = {};

    if (name) payload['name'] = name;
    if (address) payload['address'] = address;
    if (city) payload['city'] = city;
    if (state) payload['state'] = state;
    if (country) payload['country'] = country;
    if (zipcode) payload['zipcode'] = zipcode;

    const data = await AdminUser.update({ _id: toObjectId(adminId) }, payload);

    logger.log(level.info, `updateProfile Body=${req.body}`);

    return okResponse(res, messages.updated.replace("{dynamic}", "Profile"), data);
  } catch (error) {
    logger.log(level.error, `updateProfile Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
}

export const createHomeScreenImage = async (req, res) => {
  try {
    const { body, file } = req;
    const { content_type, format } = body;

    if (!file) {
      logger.log(level.info, 'createHomeScreenImage or createHomeScreenVideo no file selection found error')
      return paramMissingError(res, messages.missing_key.replace("{dynamic}", "File"));
    }

    if ([SLUG_RESOURCE_FORMAT.IMAGE, SLUG_RESOURCE_FORMAT.VIDEO].indexOf(Number(format)) === -1) {
      logger.log(level.info, 'createHomeScreenImage invalid formate type found error')
      return paramMissingError(res, messages.invalid_key.replace("{dynamic}", `File Format Type Should be ${SLUG_RESOURCE_FORMAT.IMAGE}, ${SLUG_RESOURCE_FORMAT.VIDEO}`));
    }

    const slugS3Folder = process.env.Aws_Upload_Path_For_Slug;
    const filePath = Path.parse(file.originalname);
    const fileName = generateRandomString();

    if(Number(format) === SLUG_RESOURCE_FORMAT.IMAGE){
      if (!(Object.values(IMAGE_EXTENSIONS).includes(filePath.ext))) {
        logger.log(level.info, 'createHomeScreenImage invalid file selection error')
        return badRequestError(res, messages.invalid_file_selected);
      }
    }

    if(Number(format) === SLUG_RESOURCE_FORMAT.VIDEO){
      if (!(Object.values(VIDEO_EXTENSIONS).includes(filePath.ext))) {
        logger.log(level.info, 'createHomeScreenVideo invalid file selection error')
        return badRequestError(res, messages.invalid_file_selected);
      }
    }

    if (!content_type) {
      logger.log(level.info, 'createHomeScreenImage no content type found error')
      return paramMissingError(res, messages.missing_key.replace("{dynamic}", "Content Type"));
    }

    if ([SLUG_TYPE.MORNING_IMAGE, SLUG_TYPE.EVENING_IMAGE, SLUG_TYPE.NIGHT_IMAGE].indexOf(Number(content_type)) === -1) {
      logger.log(level.info, 'createHomeScreenImage invalid content type found error')
      return paramMissingError(res, messages.invalid_key.replace("{dynamic}", `Content Type Should be ${SLUG_TYPE.MORNING_IMAGE}, ${SLUG_TYPE.EVENING_IMAGE}, ${SLUG_TYPE.NIGHT_IMAGE}`));
    }

    logger.log(level.info, `createHomeScreenImage body=${beautify(body)}`);

    const filter = { content_type };

    const isExist = await returnOnExist(Slug, filter, res, "Image", messages.already_exist.replace("{dynamic}", "Image"))
    if (isExist) return;

    const splashContent = await Slug.add({ content_type, format });
    if (!splashContent) {
      logger.log(level.info, `createHomeScreenImage Error`)
      return badRequestError(res, messages.invalid_input);
    }

    const s3Location = `${slugS3Folder}thumbnail/${fileName}${filePath.ext}`;
      await uploadFileToS3(process.env.Aws_Bucket_Name, s3Location, file).then((result, error) => {
        if (!error) {
          Slug.update({ _id: splashContent._id }, { url: s3Location });
        } else {
          logger.log(level.error, `createHomeScreenImage Error : Thumbnail upload : ${beautify(error)}`);
        }
      });

    splashContent['url'] = await getSignedUrl(process.env.Aws_Bucket_Name, s3Location);

    logger.log(level.info, `createHomeScreenImage content=${beautify(splashContent)}`);
    return okResponse(res, messages.created.replace("{dynamic}", "Therapy"), splashContent);

  } catch (error) {
    logger.log(level.error, `createHomeScreenImage Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
}

export const updateHomeScreenImage = async (req, res) => {
  try {
    const { body, file, params } = req;
    const { content_type, format } = body;
    const { slugId } = params;

    const isNotExist = await returnOnNotExist(Slug, { _id: slugId, content_type }, res, "Record", messages.not_exist.replace("{dynamic}", "Record"));
    if (isNotExist) return;

    if ([SLUG_RESOURCE_FORMAT.IMAGE, SLUG_RESOURCE_FORMAT.VIDEO].indexOf(Number(format)) === -1) {
      logger.log(level.info, 'createHomeScreenImage invalid formate type found error')
      return paramMissingError(res, messages.invalid_key.replace("{dynamic}", `File Format Type Should be ${SLUG_RESOURCE_FORMAT.IMAGE}, ${SLUG_RESOURCE_FORMAT.VIDEO}`));
    }

    let s3Location;
    if (file) {
      const slugS3Folder = process.env.Aws_Upload_Path_For_Slug;
      const filePath = Path.parse(file.originalname);
      const fileName = generateRandomString();
      s3Location = `${slugS3Folder}thumbnail/${fileName}${filePath.ext}`;

      if(Number(format) === SLUG_RESOURCE_FORMAT.IMAGE){
        if (!(Object.values(IMAGE_EXTENSIONS).includes(filePath.ext))) {
          logger.log(level.info, 'updateHomeScreenImage invalid file selection error')
          return badRequestError(res, messages.invalid_file_selected);
        }
      }
      if(Number(format) === SLUG_RESOURCE_FORMAT.VIDEO){
        if (!(Object.values(VIDEO_EXTENSIONS).includes(filePath.ext))) {
          logger.log(level.info, 'updateHomeScreenVideo invalid file selection error')
          return badRequestError(res, messages.invalid_file_selected);
        }
      }
    }
    const payload = {};

    if (format) payload['format'] = format;
    logger.log(level.info, `updateHomeScreenImage or Video body=${beautify(body)}`);

    const slug = await Slug.update({ _id: slugId }, payload);
    if (!slug) {
      logger.log(level.info, `updateSlug Error`)
      return badRequestError(res, messages.invalid_input);
    }

    if (file) {
      await uploadFileToS3(process.env.Aws_Bucket_Name, s3Location, file).then((result, error) => {
        if (!error) {
           Slug.update({ _id: slugId, content_type }, { url: s3Location, format: format });
        } else {
          logger.log(level.error, `updateHomeScreenImage or Video Error : Thumbnail upload : ${beautify(error)}`);
        }
      });
      slug['url'] = await getSignedUrl(process.env.Aws_Bucket_Name, s3Location);
    }

    logger.log(level.info, `updateHomeScreenImage or Video content=${beautify(slug)}`);
    return okResponse(res, messages.updated.replace("{dynamic}", "Splash Content"), slug);

  } catch (error) {
    logger.log(level.error, `updateHomeScreenImage Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
}

export const deleteHomeScreenImage = async (req, res) => {
  try {
    const { params } = req;
    const { slugId } = params;

    logger.log(level.info, `deleteHomeScreenImage params=${beautify(params)}`);
    let [slug] = await Slug.get({ _id: slugId });

    if (slug) {
      if ([SLUG_TYPE.MORNING_IMAGE, SLUG_TYPE.EVENING_IMAGE, SLUG_TYPE.NIGHT_IMAGE].indexOf(slug.content_type) == -1) {
        return badRequestError(res, messages.invalid_key.replace("{dynamic}", "Slug Id"))
      }
    } else {
      return badRequestError(res, messages.not_exist.replace("{dynamic}", "Slug"))
    }

    const Content = await Slug.delete({ _id: slugId });

    logger.log(level.info, `deleteHomeScreenImage content=${beautify(Content)}`);
    return okResponse(res, messages.deleted.replace("{dynamic}", "Content"));

  } catch (error) {
    logger.log(level.error, `deleteHomeScreenImage Error: ${beautify(error.message)}`);
    return internalServerError(res, error)
  }
}

export const getHomeScreenImage = async (req, res) => {
  try {
    logger.log(level.info, `getHomeScreenImage`);

    const filter = { content_type: { $in: [SLUG_TYPE.MORNING_IMAGE, SLUG_TYPE.EVENING_IMAGE, SLUG_TYPE.NIGHT_IMAGE] } }
    const content = await Slug.get(filter);
    logger.log(level.info, `content = ${beautify(content)}`);
    return okResponse(res, messages.record_fetched, content);
  } catch (error) {
    logger.log(level.error, `getHomeScreenImage Error: ${beautify(error.message)}`);
    return internalServerError(res, error)
  }
}

export const createAppVersion = async (req, res) => {
  try {
    const { body } = req;
    const { title, content_type = SLUG_TYPE.APP_ANDROID_VERSION } = body;
    logger.log(level.info, `createAppVersion body=${beautify(body)}`);

    const filter = { content_type };

    if ([SLUG_TYPE.APP_ANDROID_VERSION, SLUG_TYPE.APP_IOS_VERSION].indexOf(+content_type) == -1) {
      return badRequestError(res, messages.invalid_key.replace("{dynamic}", `Content Type Should be ${SLUG_TYPE.APP_ANDROID_VERSION} or ${SLUG_TYPE.APP_IOS_VERSION}.`));
    }

    let word = content_type == SLUG_TYPE.APP_ANDROID_VERSION ? "Android Version" : "Ios Version";

    const isExist = await returnOnExist(Slug, filter, res, word, messages.already_exist.replace("{dynamic}", word))
    if (isExist) return;

    let payload = { content_type, title }
    const version = await Slug.add(payload);
    logger.log(level.info, `createAppVersion Created: ${beautify(version)}`);

    return okResponse(res, messages.created.replace("{dynamic}", word), version);

  } catch (error) {
    logger.log(level.error, `createAppVersion Error: ${beautify(error.message)}`);
    return internalServerError(res, error)
  }
}

export const updateAppVersion = async (req, res) => {
  try {
    const { body, params } = req;
    const { title, content_type = SLUG_TYPE.APP_ANDROID_VERSION } = body;
    const { slugId } = params;
    logger.log(level.info, `updateAppVersion body=${beautify(body)} params=${beautify(params)}`);

    if ([SLUG_TYPE.APP_ANDROID_VERSION, SLUG_TYPE.APP_IOS_VERSION].indexOf(+content_type) == -1) {
      return badRequestError(res, messages.invalid_key.replace("{dynamic}", `Content Type Should be ${SLUG_TYPE.APP_ANDROID_VERSION} or ${SLUG_TYPE.APP_IOS_VERSION}.`));
    }

    let word = content_type == SLUG_TYPE.APP_ANDROID_VERSION ? "Android Version" : "Ios Version";

    const filter = { _id: slugId, content_type };

    const isNotExist = await returnOnNotExist(Slug, filter, res, word, messages.not_exist.replace("{dynamic}", word))
    if (isNotExist) return;

    if (!title) {
      logger.log(level.error, `updateAppVersion Error= ${word} is missing.`);
      return paramMissingError(res, messages.missing_key.replace("{dynamic}", word));
    }

    let payload = { title }
    const version = await Slug.update(filter, payload);
    logger.log(level.info, `updateAppVersion Updated: ${beautify(version)}`);
    return okResponse(res, messages.updated.replace("{dynamic}", word), version);
  } catch (error) {
    logger.log(level.error, `updateAppVersion Error: ${beautify(error.message)}`);
    return internalServerError(res, error)
  }
}

export const deleteAppVersion = async (req, res) => {
  try {
    const { params } = req;
    const { slugId, content_type = SLUG_TYPE.APP_ANDROID_VERSION } = params;

    logger.log(level.info, `deleteAppVersion params=${beautify(params)}`);

    if ([SLUG_TYPE.APP_ANDROID_VERSION, SLUG_TYPE.APP_IOS_VERSION].indexOf(+content_type) == -1) {
      return badRequestError(res, messages.invalid_key.replace("{dynamic}", `Content Type Should be ${SLUG_TYPE.APP_ANDROID_VERSION} or ${SLUG_TYPE.APP_IOS_VERSION}.`));
    }

    const filter = { _id: slugId, content_type };
    const version = await Slug.delete(filter);
    logger.log(level.info, `deleteAppVersion Deleted: ${beautify(version)}`);
    let word = +content_type == SLUG_TYPE.APP_ANDROID_VERSION ? "Android Version" : "Ios Version";
    return okResponse(res, messages.deleted.replace("{dynamic}", word), version);

  } catch (error) {
    logger.log(level.error, `deleteAppVersion Error: ${beautify(error.message)}`);
    return internalServerError(res, error)
  }
}

export const getAppVersion = async (req, res) => {
  try {
    const { params } = req;
    const { content_type } = params;

    logger.log(level.info, `getAppVersion content_type=${content_type}`);


    let filter;

    if (content_type) {
      if ([SLUG_TYPE.APP_ANDROID_VERSION, SLUG_TYPE.APP_IOS_VERSION].indexOf(+content_type) == -1) {
        return badRequestError(res, messages.invalid_key.replace("{dynamic}", `Content Type Should be ${SLUG_TYPE.APP_ANDROID_VERSION} or ${SLUG_TYPE.APP_IOS_VERSION}.`));
      }
      filter = { content_type }
    } else {
      filter = {
        $or: [{ content_type: SLUG_TYPE.APP_ANDROID_VERSION }, { content_type: SLUG_TYPE.APP_IOS_VERSION }]
      }
    }

    const version = await Slug.get(filter);
    logger.log(level.info, `getAppVersion version: ${beautify(version)}`);
    return okResponse(res, messages.record_fetched, content_type ? (version.length > 0 ? version[0] : {}) : version);

  } catch (error) {
    logger.log(level.error, `getAppVersion Error: ${beautify(error.message)}`);
    return internalServerError(res, error)
  }
}

export const getAllNotification = async (req, res) => {
  try {
    const { query } = req;
    const { option = {} } = query;
    const { sort = { created_at: -1 } } = option;
    option['sort'] = sort;
    logger.log(level.info, `Admin getAllNotification options=${beautify(option)}`);
    const filter = await parseSearchOptions(option);
    logger.log(level.info, `getAllNotification filter=${beautify(filter)}`);
    const notification = await Notification.get(filter, null, option, { path: "user" });
    const count = await notification.length;
    return okResponse(res, messages.record_fetched, notification, count);
  } catch (error) {
    logger.log(level.error, `getAllNotificationByAdmin Error: ${beautify(error.message)}`);
    return internalServerError(res, error)
  }
};

export const getAllScheduleNotification = async (req, res) => {
  try {
    const { query } = req;
    const { option = {} } = query;
    const { sort = { schedule_time: -1 } } = option;
    option['sort'] = sort;


    logger.log(level.info, `Admin getAllScheduleNotification options=${beautify(option)}`);
     const filter = await parseSearchOptions(option);
    logger.log(level.info, `getAllScheduleNotification filter=${beautify(filter)}`);
    const notification = await scheduleNotification.get(filter, null, option);
    const count = await notification.length;
    for (const item of notification) {
      if(item?.image){
        const url = await getSignedUrl(process.env.Aws_Bucket_Name, item?.image);
        item['image'] = url
      }
    }
    return okResponse(res, messages.record_fetched, notification, count);

  } catch (error) {
    logger.log(level.error, `getAllScheduleNotificationByAdmin Error: ${beautify(error.message)}`);
    return internalServerError(res, error)
  }
};

export const updateScheduleNotification = async (req, res) => {
  try {
    const {body, file} = req;
    const {scheduleNotificationId} = req.params;
    const {users = null, title = null, message = null, schedule_time = null} = body;
    const s3Folder = process.env.Aws_Upload_Path_For_Notification;
    let filePath, fileName, s3Location;
    if (file) {
      filePath = Path.parse(file.originalname);
      fileName = generateRandomString();
      if (!(Object.values(IMAGE_EXTENSIONS).includes(filePath.ext))) {
        logger.log(level.info, 'updateScheduleNotification invalid file selection error');
        return badRequestError(res, messages.invalid_file_selected);
      }
      s3Location = `${s3Folder}thumbnail/${fileName}${filePath.ext}`;
      logger.log(level.info, `s3Location : ${s3Location}`);
      uploadFileToS3(process.env.Aws_Bucket_Name, s3Location, file).then((result, error) => {
        if (error) {
          logger.log(level.error, `updateScheduleNotification Error : Thumbnail upload : ${beautify(error)}`);
        }
      });
    }

    const payload = {};

    if (users) payload['user_ids'] = users;
    if (title) payload['title'] = title;
    if (message) payload['description'] = message;
    if (schedule_time) payload['schedule_time'] = schedule_time;
    if(file) payload['image'] = s3Location;
    const data = await scheduleNotification.update({_id: toObjectId(scheduleNotificationId)}, payload);
    logger.log(level.info, `updateScheduleNotification Body=${data}`);
    return okResponse(res, messages.updated.replace("{dynamic}", "schedule notification"), data);

  } catch (error) {
    logger.log(level.error, `updateScheduleNotification Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
};

export const deleteScheduleNotification = async (req, res) => {
  try {
    const { params } = req;
    const { scheduleNotificationId } = params;

    logger.log(level.info, `scheduleNotificationId params=${beautify(params)}`);
    const schNotification = await scheduleNotification.delete({ _id: scheduleNotificationId });
    if (!schNotification) {
      logger.log(level.info, 'deleteScheduleNotification error');
      return badRequestError(res, messages.invalid_input);
    }
    logger.log(level.info, `deleteScheduleNotification question=${beautify(schNotification)}`);
    return okResponse(res, messages.deleted.replace("{dynamic}", "schedule notification"));

  } catch (error) {
    logger.log(level.error, `deleteScheduleNotification Error: ${beautify(error.message)}`);
    return internalServerError(res, error)
  }
};

export const downloadUserReport = async (req, res) => {
  try {
    const { body } = req;
    const { name, gender, age, email, fear = [], smoking = [], pranayama = [], meditation = [] } = body;
    logger.log(level.info, `downloadUserReport data: ${beautify(body)}`);

    if (!email) {
      return paramMissingError(res, messages.missing_key.replace("{dynamic}", "Email"))
    }

    const fear_score = _.sum(fear);
    const smoking_score = _.sum(smoking);
    const pranayama_score = _.sum(pranayama);
    const meditation_score = _.sum(meditation);
    const obj = {
      NAME: name,
      GENDER: gender,
      AGE: age,
      EMAIL: email,
      FEAR: {
        SCORE: fear_score,
        ...getTitleAndText('FEAR', fear_score)
      },
      SMOKING: {
        SCORE: smoking_score,
        ...getTitleAndText('SMOKING', smoking_score)
      },
      PRANAYAMA: {
        SCORE: pranayama_score,
        ...getTitleAndText('PRANAYAMA', pranayama_score)
      },
      MEDITATION: {
        SCORE: meditation_score,
        ...getTitleAndText('MEDITATION', meditation_score)
      }
    }
    logger.log(level.info, `downloadUserReport Final data: ${beautify(obj)}`);

    await UserReportHtml(process.env.HOST_URL, obj).then(async (data) => {
      const browser = await puppeteer.launch({ headless: true });
      const page = await browser.newPage();
      await page.goto('about:blank');
      await page.emulateMediaType('screen');
      await page.setContent(data);
      const path = Path.join(__dirname, "src", "public", "reports", `/Report-${Date.now()}.pdf`);
      await page.pdf({ path, format: 'A4', printBackground: true })

      await browser.close();
      await SendEmail(obj.EMAIL, 'user_report', path).then(result => {
        fs.unlinkSync(path);
      })
    });
    return okResponse(res, messages.email_sent);

  } catch (error) {
    logger.log(level.error, `downloadUserReport Error: ${beautify(error.message)}`);
    return internalServerError(res, error)
  }
}

function getTitleAndText(criteria, score) {
  switch (criteria) {
    case 'FEAR':
      if (score >= 11 && score <= 15) {
        return {
          TITLE: 'High levels of Anxiety',
          TEXT: 'Consult Mental Health Professional. CBT Therapies and daily sleep meditation are highly recommended.'
        }
      } else if (score >= 6 && score <= 10) {
        return {
          TITLE: 'Moderate Levels of Anxiety',
          TEXT: 'Therapies along with regular Mindfulness Meditation are highly recommended.'
        }
      } else if (score >= 0 && score <= 5) {
        return {
          TITLE: 'Normal Anxiety Levels',
          TEXT: 'Mindfulness and concentration Meditation are recommended for further well-being.'
        }
      }
      break;
    case 'SMOKING':
      if (score >= 11 && score <= 15) {
        return {
          TITLE: 'High levels of Addiction.',
          TEXT: 'Consult Mental Health Professional. Healing and Quitting Therapies are highly recommended.'
        }
      } else if (score >= 6 && score <= 10) {
        return {
          TITLE: 'Moderate Levels of Addiction',
          TEXT: 'Behavior Therapies along with regular breathing exercises are highly recommended.'
        }
      } else if (score >= 0 && score <= 5) {
        return {
          TITLE: 'Normal Addiction Levels',
          TEXT: 'Therapies along with regular Meditation are recommended.'
        }
      }
      break;
    case 'PRANAYAMA':
      if (score >= 11 && score <= 15) {
        return {
          TITLE: 'Lung Capacity Weak',
          TEXT: 'Learn Pranayamas or Yogic Breathing Exercises and Practice twice regularly.'
        }
      } else if (score >= 6 && score <= 10) {
        return {
          TITLE: 'Breathing Needs Improvement',
          TEXT: 'Regular breathing exercises are highly recommended.'
        }
      } else if (score >= 0 && score <= 5) {
        return {
          TITLE: 'Healthy Breathing Habits',
          TEXT: 'Incorporate Breathing Exercises into your daily routine for further well-being.'
        }
      }
      break;
    case 'MEDITATION':
      if (score >= 11 && score <= 15) {
        return {
          TITLE: 'Higher Stress Levels',
          TEXT: 'Meditate twice a day to relax from excessive stress and concentrate on important tasks.'
        }
      } else if (score >= 6 && score <= 10) {
        return {
          TITLE: 'Moderate Stress Levels',
          TEXT: 'Behavior Therapies along with regular breathing exercises are highly recommended.'
        }
      } else if (score >= 0 && score <= 5) {
        return {
          TITLE: 'Normal Stress Levels',
          TEXT: 'Master the art of mindfulness and concentration in your daily routine for growth and well-being.'
        }
      }
      break;
  }
}

export const getApplicationVersion = async (req, res) => {
  try {
    const [version] = await Appversion.get();
    logger.log(level.info, `Admin getApplicationVersion options=${beautify(version)}`);
    return okResponse(res, messages.record_fetched,version);
    
  } catch (error) {
    logger.log(level.error, `getApplicationVersion Error: ${beautify(error.message)}`);
    return internalServerError(res, error)
  }
}

export const updateApplicationVersion = async (req, res) => {
  try {
    
    const { body, params } = req;
    const { appVersionId } = params;
    let { androidVersion = null, iOSVersion = null, androidForceUpdate , iOSForceUpdate } = body;


    const payload = {};
    if (androidVersion) payload['androidVersion'] = androidVersion;
    if (iOSVersion) payload['iOSVersion'] = iOSVersion;
    if (androidForceUpdate == 0 || androidForceUpdate == 1) payload['androidForceUpdate'] = androidForceUpdate;
    if (iOSForceUpdate ==0 || iOSForceUpdate == 1) payload['iOSForceUpdate'] =iOSForceUpdate;

    const isNotExist = await returnOnNotExist(Appversion, toObjectId(appVersionId), res, messages.not_exist.replace("{dynamic}"),"App VersionId Not Exist.")
    if (isNotExist) return;

    logger.log(level.info, `Admin updateApplicationVersion options=${beautify(payload)}`);
    const updateVersion = await Appversion.update({_id:appVersionId},payload);
    return okResponse(res, messages.record_fetched,updateVersion);
    
  } catch (error) {
    logger.log(level.error, `updateApplicationVersion Error: ${beautify(error.message)}`);
    return internalServerError(res, error)
  }
}

export const createFreeUserTrail = async (req, res) => {
  try {
    const { body} = req;
    let { user_id,startTrial,endTrial,trialId=null, userTrial } = body;

    logger.log(level.info, `createAppVersion body=${beautify(body)}`);
    
    user_id = toObjectId(user_id)
    
    const isNotExist = await returnOnNotExist(User, toObjectId(user_id), res, messages.not_exist.replace("{dynamic}"),"user_id Not Exist.");
    if (isNotExist) return;

    const [Users] = await User.get({_id:user_id});
  
    const dbvalue = await Users.userTrial;
    const isUserTrial = typeof userTrial != 'undefined' ?  userTrial : dbvalue;

    if(isUserTrial===false ){

        if(dbvalue){
          const updateTrialUserTrue = await User.update({_id:user_id},{userTrial:userTrial});
        }

        let filter = { user_id };
        const isTrialUserExist = await returnOnExist(TrialUsers, filter, res, "User Trial", messages.already_exist.replace("{dynamic}", "This User Trial is"));
          if (isTrialUserExist)return;
            
          let currentDate = new Date();

          startTrial = new Date(startTrial);
          endTrial = new Date(endTrial);

          // Set both startTrial and currentDate to the same time of day
          startTrial.setHours(0, 0, 0, 0);
          endTrial.setHours(0, 0, 0, 0);
          currentDate.setHours(0, 0, 0, 0);

          if( startTrial.getTime() >= currentDate.getTime() ){}else if(startTrial < currentDate){
            return badRequestError(res, messages.invalid_key.replace("{dynamic}", `Start Trial date should be greater than the current date.`));
          }

          if( endTrial.getTime() > startTrial.getTime() ){}else if(endTrial.getTime() <= startTrial.getTime()){
            return badRequestError(res, messages.invalid_key.replace("{dynamic}", `End Trial date should be greater than the Start Trial date.`));
          }
   
          let payload = { user_id,startTrial,endTrial }

          const TrialUserData = await TrialUsers.add(payload);
        
          logger.log(level.info, `createAppVersion Created: ${beautify(TrialUserData)}`);

          if(TrialUserData){
            const updateTrialUserTrue = await User.update({_id:user_id},{userTrial:true});
            logger.log(level.info, `User Trial Updated: ${beautify(updateTrialUserTrue)}`);

            const updatedTrialUserData = await TrialUsers.get({user_id:user_id});

            return okResponse(res, messages.created.replace("{dynamic}", "User Trial"), updatedTrialUserData);
          }
        
    }
    else if(isUserTrial===true){
      
      let filter = { _id: user_id };
    
      let trialUserDoc = await TrialUsers.get({
        filter,
        $or: [{ is_deleted: false }, { is_deleted: { $exists: false } }],
      });
      
      trialUserDoc =trialUserDoc[0]
      
      const dbStartTrial = trialUserDoc.startTrial;
      const dbEndTrial = trialUserDoc.endTrial;

      if(dbStartTrial){
        startTrial = typeof startTrial != 'undefined' ?  startTrial : dbStartTrial;
      }
      if(dbEndTrial){
        endTrial = typeof endTrial != 'undefined' ?  endTrial : dbEndTrial;
      }

      const isTrialUsersNotExist = await returnOnNotExist(TrialUsers, toObjectId(trialId), res, messages.not_exist.replace("{dynamic}"),"trialId Not Exist.");
      if (isTrialUsersNotExist) return;
      
      let currentDate = new Date();
      
      startTrial = new Date(startTrial);
      endTrial = new Date(endTrial);
      
      currentDate.setHours(0, 0, 0, 0);
      
      const payload = {};
      
        if (startTrial) {
            if( startTrial.getTime() >= currentDate.getTime() ){
              payload['startTrial'] = startTrial
            }else if(startTrial < currentDate){
              return badRequestError(res, messages.invalid_key.replace("{dynamic}", `Start Trial date should be greater than the current date.`));
            }
            
          } 
        
        if (endTrial){
          if( endTrial.getTime() > startTrial.getTime() ){
            payload['endTrial'] = endTrial
          }else if(endTrial.getTime() <= startTrial.getTime()){
            return badRequestError(res, messages.invalid_key.replace("{dynamic}", `End Trial date should be greater than the Start Trial date.`));
          }
        }
        
        logger.log(level.info, `Admin updateApplicationVersion options=${beautify(payload)}`);
        
        const updateTrialUser = await TrialUsers.update({_id:trialId},payload);

        if(userTrial){
          userTrial = Boolean(userTrial);
        }

        const updateTrialUserdata = await User.update({_id:user_id},{userTrial:userTrial});

        logger.log(level.info, `Admin updateApplicationVersion options=${beautify(updateTrialUserdata)}`);
        
        const trialUsersData = await TrialUsers.get({user_id:user_id});
        
        return okResponse(res, messages.record_fetched,trialUsersData);
        
    }
  } catch (error) {
    logger.log(level.error, `createFreeUserTrail Error: ${beautify(error.message)}`);
    return internalServerError(res, error)
  }
}

export const updateFreeUserTrail = async (req, res) => {
  try {
    const { body, params } = req;
    const { userId } = params;
    let { userTrial, startTrial, endTrial } = body;
    
    const payload = {};
    // Parse date strings into Date objects
    const parseDate = (dateStr) => {
      const [day, month, year] = dateStr.split('-');
      return new Date(`${year}-${month}-${day}`);
    };


    // payload['userTrial']= Boolean(userTrial);
    if (userTrial) payload['userTrial'] = Boolean(userTrial);
    payload['userTrial'] = userTrial;

    if (startTrial) {
      startTrial = parseDate(startTrial);
      payload['startTrial'] = startTrial
    } 

    if (endTrial){
      endTrial = parseDate(endTrial);
      payload['endTrial'] = endTrial
    } 


/*     const isNotExist = await returnOnNotExist(TrialUsers, toObjectId(userId), res, messages.not_exist.replace("{dynamic}"),"userId Not Exist.")
    if (isNotExist) return; */
    logger.log(level.info, `Admin updateApplicationVersion options=${beautify(payload)}`);

    const updateTrialUser = await TrialUsers.update({_id:userId},payload);
    const updatedTrialUserData = await TrialUsers.get(filter, null, option);

    return okResponse(res, messages.record_fetched,updatedTrialUserData);

  } catch (error) {
    logger.log(level.error, `createFreeUserTrail Error: ${beautify(error.message)}`);
    return internalServerError(res, error)
  }
}

export const getAllFreeUserTrail = async (req, res) => {
  try {
    const { query } = req;
    const { option = {} } = query;
    
    const { sort = { created_at: -1 } } = option;
    option['sort'] = sort;

    logger.log(level.info, `Admin getAllFreeUserTrail options=${beautify(option)}`);
    
    //const filter = await parseSearchOptions(option);
    const filter = { is_deleted: false };
    logger.log(level.info, `getAllFreeUserTrail filter=${beautify(filter)}`);

    const trialUsers = await TrialUsers.get(filter, null, option);
    const count = await TrialUsers.count(filter);
    return okResponse(res, messages.record_fetched, trialUsers, count);
    
  } catch (error) {
    logger.log(level.error, `getAllFreeUserTrail Error: ${beautify(error.message)}`);
    return internalServerError(res, error)
  }
}