import HTTPStatus from "http-status";
import Path from "path";

import messages from "../shared/constant/messages.const.js";
import Therapy from "../models/therapy.model.js";
import SubCategory from "../models/sub_category.model.js";
import SubCategoryTherapy from "../models/sub_category_therapies.model.js";
import { internalServerError, beautify, generateRandomString, okResponse, paramMissingError, badRequestError, toObjectId, parseSearchOptions } from "../shared/utils/utility.js";
import { logger, level } from "../config/logger.js";
import Favorites from "../models/favorite.model.js";
import TherapyResources from "../models/therapy_resources.model.js";
import { getSignedUrl, uploadFileToS3 } from "../shared/services/file-upload/aws-s3.service.js";
import { IMAGE_EXTENSIONS } from "../shared/constant/types.const.js";
import UserProgress from "../models/user_progress.model.js";
import { returnOnNotExist } from "../shared/services/database/query.service.js";
import UserAnswers from "../models/user_answers.model.js";
import ReviewRating from "../models/review_rating.model.js";
import { getProgressOfTherapies, getRecentTherapyPipeline, getTherapyWithProgress } from "../shared/pipeline/therapy.pipeline.js";
import { getAllTherapyList } from "../shared/pipeline/admin.TherapyList.pipeline.js";
import Resource from "../models/resource.model.js";

const deletedCondition = { is_deleted: false };

export const getRecentTherapy = async (req, res, next) => {
  try {
    const { query } = req;
    const { option = {} } = query;
    const { sort = { updated_at: -1 } } = option;

    option['sort'] = sort;

    let { pipeline } = await getRecentTherapyPipeline(option);
    let therapy = await SubCategoryTherapy.aggregate(pipeline);
    let therapy_ids = therapy.map(item => item.therapy_id)
    const filter = { user_id: toObjectId(req['currentUserId']), therapy_id: { $in: [...therapy_ids] } };
    let progressPipeline = await getProgressOfTherapies(filter)
    let ratings = await ReviewRating.get(filter);
    const progress = await UserProgress.aggregate(progressPipeline);
    therapy = await integrateProgressWithTherapy(progress, therapy, ratings);
    const subCategoryIds = therapy.map(item => item.sub_category_id);
    const abc = subCategoryIds.flat(1).filter((item, index) => subCategoryIds.flat(1).indexOf(item) === index);
    const subCategory = (await SubCategory.get({ category_id: "63a5d3307edc82f25b85f751" })).map(item => item.id);
    const intersection = abc?.filter(element => subCategory?.includes(element));
    let array = [];
    intersection.forEach(i => {
      const idWiseData = therapy.filter(item => item.sub_category_id.includes(i))
      idWiseData.reverse();
      idWiseData.forEach((item, index) => {
        item.index = index
      });
      array.push(idWiseData)
    });
    let therapiesData = array.flat(1);
    const totalCount = therapiesData?.length;
    if (((option["'offset'"]) * 10) > totalCount - 1) {
      therapiesData = [];
    }
    const start = Math.min(totalCount - 1, ((option["'offset'"]) * 10));
    const end = Math.min(totalCount, ((option["'offset'"]) * 10) + option["'limit'"]);
      let data = [];
      if (start && end) {
          data = therapiesData.slice(start, end)
      } else {
          data = therapiesData
      }
    data.forEach(item => (
        item.therapy.sub_category_id = item.sub_category_id,
        item.therapy.therapy_id = item.therapy_id,
        item.therapy.completed = item.completed,
        item.therapy.is_review_submitted = item.is_review_submitted,
        item.therapy.index = item.index
    ));

    for (const item of data) {
      if (item.therapy.thumbnail_url) {
        item['therapy']['thumbnail_url'] = await getImageLink(item.therapy.thumbnail_url)
      }
    }

    const therapyData = data.map(item => item.therapy);

    return okResponse(res, messages.record_fetched, therapyData, totalCount);

  } catch (error) {
    logger.log(level.error, `getRecentTherapy Error: ${beautify(error.message)}`);
    return internalServerError(res, error)
  }
}

export const createTherapy = async (req, res) => {
  try {
    const { body, file } = req;
    const { name, description, duration, sub_category_id, format, is_upcomming = false } = body;

    if (!file) {
      logger.log(level.info, 'createTherapy no file selection found error')
      return paramMissingError(res, messages.missing_key.replace("{dynamic}", "File"));
    }

    const therapyS3Folder = process.env.Aws_Upload_Path_For_Therapy;
    const filePath = Path.parse(file.originalname);
    const fileName = generateRandomString();

    if (!(Object.values(IMAGE_EXTENSIONS).includes(filePath.ext))) {
      logger.log(level.info, 'createTherapy invalid file selection error')
      return badRequestError(res, messages.invalid_file_selected);
    }

    logger.log(level.info, `createTherapy body=${beautify(body)}`);

    const notExist = await returnOnNotExist(SubCategory, { _id: sub_category_id, ...deletedCondition }, res, "Sub Category", messages.not_exist.replace("{dynamic}", "Sub Category"));
    if (notExist) return;

    const therapy = await Therapy.add({ name, description, duration, format, session_counts: 0, status: 1, is_upcomming });
    if (!therapy) {
      logger.log(level.info, `createTherapy Error`)
      return badRequestError(res, messages.invalid_input);
    }

    const s3Location = `${therapyS3Folder}${therapy.id}/thumbnail/${fileName}${filePath.ext}`;
    uploadFileToS3(process.env.Aws_Bucket_Name, s3Location, file).then((result, error) => {
      if (!error) {
        Therapy.update({ _id: therapy._id }, { thumbnail_url: s3Location });
      } else {
        logger.log(level.error, `createTherapy Error : Thumbnail upload : ${beautify(error)}`);
      }
    });

    await SubCategoryTherapy.add({ therapy_id: therapy._id, sub_category_id });

    therapy['thumbnail_url'] = await getSignedUrl(process.env.Aws_Bucket_Name, s3Location);

    logger.log(level.info, `createTherapy therapy=${beautify(therapy)}`);
    return okResponse(res, messages.created.replace("{dynamic}", "Therapy"), therapy);

  } catch (error) {
    logger.log(level.error, `createTherapy Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
}

export const updateTherapy = async (req, res) => {
  try {
    const { body, params, file = null } = req;
    const { name, description, format, duration, status, is_upcomming } = body;
    const { therapyId } = params;

    logger.log(level.info, `updateTherapy body=${beautify(body)} \n params=${beautify(params)}`);

    const therapyS3Folder = process.env.Aws_Upload_Path_For_Therapy;
    let filePath, fileName, s3Location;
    if (file) {
      filePath = Path.parse(file.originalname);
      fileName = generateRandomString();
      if (!(Object.values(IMAGE_EXTENSIONS).includes(filePath.ext))) {
        logger.log(level.info, 'createTherapy invalid file selection error')
        return badRequestError(res, messages.invalid_file_selected);
      }
    }

    const notExist = await returnOnNotExist(Therapy, { _id: therapyId, ...deletedCondition }, res, "Therapy", messages.not_exist.replace("{dynamic}", "Therapy"));
    if (notExist) return;

    const payload = {};

    if (name) payload['name'] = name;
    if (format) payload['format'] = format;
    if (description) payload['description'] = description;
    if ('status' in body) payload['status'] = status;
    if (duration) payload['duration'] = duration;
    if (is_upcomming != undefined && is_upcomming != null) payload['is_upcomming'] = is_upcomming;

    const therapy = await Therapy.update({ _id: therapyId }, payload);
    if (!therapy) {
      logger.log(level.info, `updateTherapy Error`)
      return badRequestError(res, messages.invalid_input);
    }

    if (file) {
      s3Location = `${therapyS3Folder}${therapyId}/thumbnail/${fileName}${filePath.ext}`;
      logger.log(level.info, `\n\ns3Location :::: ${s3Location}`);
      uploadFileToS3(process.env.Aws_Bucket_Name, s3Location, file).then((result, error) => {
        if (!error) {
          Therapy.update({ _id: therapyId }, { thumbnail_url: s3Location });
        } else {
          logger.log(level.error, `updateTherapy Error : Thumbnail upload : ${beautify(error)}`);
        }
      });
      therapy['thumbnail_url'] = await getSignedUrl(process.env.Aws_Bucket_Name, s3Location);
    }

    logger.log(level.info, `updateSubCategory therapy=${beautify(therapy)}`);
    return okResponse(res, messages.updated.replace("{dynamic}", "Therapy"), therapy);

  } catch (error) {
    logger.log(level.error, `updateTherapy Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
}

export const deleteTherapy = async (req, res) => {
  try {
    const { params } = req;
    const { therapyId } = params;
    const deletePayload = { is_deleted: true, deleted_at: new Date().toISOString() };

    logger.log(level.error, `deleteTherapy Params: ${beautify(params)}`);

    const deletedTherapy = await Therapy.update({ _id: therapyId, ...deletedCondition }, deletePayload);
    await SubCategoryTherapy.update({ therapy_id: therapyId }, deletePayload);

    await Favorites.deleteMany({ therapy_id: therapyId });

    const multiLinkedResource = {
      $and: [
        { $expr: { $gt: [{ $size: "$therapy_ids" }, 1] } },
        { therapy_ids: { $in: [therapyId] } },
        deletedCondition
      ]
    }
    const therapyResources_record = await TherapyResources.get(multiLinkedResource);
    const therapyResource_records_ids = therapyResources_record.map(item => item._id);
    for (let i = 0; i < therapyResource_records_ids.length; i++) {
      const filter = { _id: therapyResource_records_ids[i] }
      await TherapyResources.update(filter, { $pull: { therapy_ids: { $in: [therapyId] } } });
    }
    logger.log(level.info, `therapy resource multi linked`);

    const singleLinkedResource = {
      $and: [
        { $expr: { $lte: [{ $size: "$therapy_ids" }, 1] } },
        { therapy_ids: { $in: [therapyId] } },
        deletedCondition
      ]
    }
    const therapyResources = await TherapyResources.get(singleLinkedResource);
    const resourceIds = therapyResources.map(item => item.resource_id);
    const therapyResources_records = therapyResources.map(item => item._id);
    for (let i = 0; i < therapyResources_records.length; i++) {
      const filter = { _id: therapyResources[i], ...deletedCondition };
      await TherapyResources.update(filter, deletePayload);
    }
    logger.log(level.info, `therapy resource single linked`);
    for (let i = 0; i < resourceIds.length; i++) {
      await Resource.update({ _id: resourceIds[i], ...deletedCondition }, deletePayload);
    }
    logger.log(level.info, `resource deleted: ${beautify(resourceIds)}`);

    logger.log(level.info, `deleteTherapy therapy =${beautify(deletedTherapy)}`);
    return okResponse(res, messages.deleted.replace("{dynamic}", "Therapy"));

  } catch (error) {
    logger.log(level.error, `deleteTherapy Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
}

export const linkTherapyToSubCategory = async (req, res) => {
  try {
    const { params, body } = req;
    const { therapyId } = params;
    const { sub_category_ids } = body;

    logger.log(level.info, `linkTherapyToSubCategory body=${beautify(body)} \n params=${beautify(params)}`);

    const notExist = await returnOnNotExist(Therapy, { _id: therapyId, ...deletedCondition }, res, "Therapy", messages.not_exist.replace("{dynamic}", "Therapy"));
    if (notExist) return;

    const uniqueSubCategoryIds = [...new Set(sub_category_ids)];
    const subCategoryCount = await SubCategory.count({ _id: { $in: uniqueSubCategoryIds }, ...deletedCondition });
    if (subCategoryCount != uniqueSubCategoryIds.length) {
      logger.log(level.info, 'linkTherapyToSubCategory sub category not exist error')
      return badRequestError(res, messages.invalid_input);
    }

    let subCategoryIds = uniqueSubCategoryIds;

    let subCategoryTherapy = await SubCategoryTherapy.get({ therapy_id: therapyId, ...deletedCondition });
    if (subCategoryTherapy.length) {
      const temp = subCategoryTherapy[0].sub_category_id.length ? subCategoryTherapy[0].sub_category_id.toString().split(",") : [];
      subCategoryIds = [...new Set([...subCategoryIds, ...temp])];
    }

    subCategoryTherapy = await SubCategoryTherapy.update({ therapy_id: therapyId, ...deletedCondition }, { sub_category_id: subCategoryIds }, { path: "sub_category" });

    logger.log(level.info, `linkTherapyToSubCategory therapy resources=${beautify(subCategoryTherapy)}`);
    return okResponse(res, messages.updated.replace("{dynamic}", "Therapy Sub Category"), subCategoryTherapy);

  } catch (error) {
    logger.log(level.error, `linkTherapyToSubCategory Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
}

export const unlinkTherapyToSubCategory = async (req, res) => {
  try {
    const { params, body } = req;
    const { therapyId } = params;
    const { sub_category_ids } = body;

    logger.log(level.info, `unlinkTherapyToSubCategory body=${beautify(body)} \n params=${beautify(params)}`);
    const notExist = await returnOnNotExist(Therapy, { _id: therapyId, ...deletedCondition }, res, "Therapy", messages.not_exist.replace("{dynamic}", "Therapy"));
    if (notExist) return;

    const uniqueSubCategoryIds = [...new Set(sub_category_ids)];
    const subCategoryCount = await SubCategory.count({ _id: { $in: uniqueSubCategoryIds }, ...deletedCondition });
    if (subCategoryCount != uniqueSubCategoryIds.length) {
      logger.log(level.info, 'unlinkTherapyToSubCategory therapy not exist error')
      return badRequestError(res, messages.invalid_input);
    }

    const subCategoryTherapy = await SubCategoryTherapy.update({ therapy_id: therapyId, ...deletedCondition }, { $pull: { sub_category_id: { $in: uniqueSubCategoryIds } } }, { path: "sub_category" });

    logger.log(level.info, `unlinkTherapyToSubCategory therapy resources=${beautify(subCategoryTherapy)}`);
    return okResponse(res, messages.updated.replace("{dynamic}", "Therapy Sub Category"), subCategoryTherapy);

  } catch (error) {
    logger.log(level.error, `unlinkTherapyToSubCategory Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
}

export const getUserTherapiesWithProgress = async (req, res) => {
  try {
    const { query } = req;
    const { is_completed, categoryId = null, option = {} } = query;
    logger.log(level.info, `getUserTherapiesWithProgress option=${beautify(option)}`);

    var filter = { user_id: toObjectId(req['currentUserId']) }
    if (categoryId) {
      const subCategories = (await SubCategory.get({ category_id: categoryId })).map(subcat => subcat._id);
      logger.log(level.info, `getUserTherapiesWithProgress subCategories: ${beautify(subCategories)}`);
      if (subCategories.length > 0) {
        filter = { ...filter, sub_category_id: { $in: [...subCategories] } }
      }
    }
    const { pipeline, countPipeline } = await getTherapyWithProgress(filter, option, is_completed);
    let therapy = await UserProgress.aggregate(pipeline);
    let count = await UserProgress.aggregate(countPipeline);
    logger.log(level.info, `getUserTherapiesWithProgress ongoing therapy=${beautify(therapy)}`);
    return okResponse(res, messages.record_fetched, therapy, count?.length);

  } catch (error) {
    logger.log(level.error, `getUserTherapiesWithProgress Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
}

export const getRecommendedTherapyList = async (req, res) => {
  try {
    const userId = req['currentUserId'];

    const userAnswers = await UserAnswers.get({ user_id: userId, question_answer: true }, null, null, { path: 'question' });
    logger.log(level.info, `userAnswers = ${beautify(userAnswers)}`);
    let subCatIds = userAnswers.reduce((pre, cur) => {
      if (!pre.length) pre = [];
      const codeIds = cur.question?.combination_code_ids;
      if (codeIds) {
        pre = [...pre, ...codeIds];
      }
      return pre;
    }, {});
    let itm, elem = [], obj = {};
    for (var i = 0; i < subCatIds.length; i++) {
      itm = subCatIds[i];
      if (!itm) continue;
      if (obj[itm] == undefined) obj[itm] = 1;
      else ++obj[itm];
    }
    for (var key in obj) elem[elem.length] = key;
    const sortedArray = elem.sort(function (a, b) {
      return obj[b] - obj[a];
    });
    const subCats = sortedArray.length <= 2 ? sortedArray : [sortedArray[0], sortedArray[1]];
    var therapy = (await SubCategoryTherapy.get({ sub_category_id: { $in: subCats }, ...deletedCondition }, null, null, { path: 'therapy' }));

    let therapy_ids = therapy.map(item => item._id);
    const filter = { user_id: toObjectId(req['currentUserId']), therapy_id: { $in: [...therapy_ids] } };
    let progressPipeline = await getProgressOfTherapies(filter)
    const progress = await UserProgress.aggregate(progressPipeline);
    let ratings = await ReviewRating.get(filter);
    therapy = await integrateProgressWithTherapy(progress, therapy, ratings);

    const subCategoryIds = therapy.map(item => item.sub_category_id);
    const abc = subCategoryIds.flat(1).filter((item, index) => subCategoryIds.flat(1).indexOf(item) === index);
    const subCategory = (await SubCategory.get({ category_id: "63a5d3307edc82f25b85f751" })).map(item => item.id);
    const intersection = abc?.filter(element => subCategory?.includes(element));
    let array = [];
    intersection.forEach(i => {
      const idWiseData = therapy.filter(item => item.sub_category_id.includes(i));
      idWiseData.forEach((item, index) => {
        item.index = index
      });
      array.push(idWiseData)
    });
    const therapiesData = array.flat(1);

    therapiesData.forEach(item => (
        item.therapy.sub_category_id = item.sub_category_id,
            item.therapy.therapy_id = item.therapy_id,
            item.therapy.completed = item.completed,
            item.therapy.is_review_submitted = item.is_review_submitted,
            item.therapy.index = item.index
    ));

    const therapyData = therapiesData.map(item => item.therapy);

    return okResponse(res, messages.record_fetched, therapyData, therapyData?.length);

  } catch (error) {
    logger.log(level.error, `getRecommendedTherapyList Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
}

export const addTherapyReviewRating = async (req, res) => {
  try {
    const { body } = req;
    const { rating, review = null, therapyId } = body;

    logger.log(level.info, `addTherapyReviewRating body=${beautify(body)}`);

    const notExist = await returnOnNotExist(Therapy, { _id: therapyId }, res, "Therapy", messages.not_exist.replace("{dynamic}", "Therapy"));
    if (notExist) return;

    if (rating < 0 || rating > 5) {
      logger.log(level.info, 'addTherapyReviewRating invalid rating number error');
      return badRequestError(res, messages.invalid_input);
    }

    await ReviewRating.add({ user_id: req['currentUserId'], rating, review, therapy_id: therapyId, resource_id: null });

    return okResponse(res, messages.rating_added.replace("{dynamic}", "Therapy"));

  } catch (error) {
    logger.log(level.error, `addTherapyReviewRating Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
}

export const getTherapyReviewRatings = async (req, res) => {
  try {
    const { params, query } = req;
    const { therapyId } = params;
    const { option = {} } = query;

    logger.log(level.info, `getTherapyReviewRatings params=${beautify(params)}`);

    const reviewRatings = await ReviewRating.get({ therapy_id: therapyId }, null, option);
    const total = await ReviewRating.count({ therapy_id: therapyId });

    return okResponse(res, messages.record_fetched, reviewRatings, total);

  } catch (error) {
    logger.log(level.error, `getTherapyReviewRatings Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
}

export const getTherapiesList = async (req, res) => {
  try {
    const { query } = req;
    const { categoryId = null, subCategoryId = null, option = {} } = query;

    logger.log(level.info, `getTherapiesList query=${beautify(query)}, ${option.limit}`);

    const filter = { is_deleted: false };
    if (subCategoryId) {
      filter['sub_category_id'] = subCategoryId
    } else {
      if (categoryId) {
        const subCategories = (await SubCategory.get({ category_id: categoryId })).map(subCat => subCat._id);
        logger.log(level.info, `getTherapiesList subCategories: ${beautify(subCategories)}`);
        if (subCategories.length > 0) {
          filter['sub_category_id'] = { $in: [...subCategories] }
        } else {
          return okResponse(res, messages.record_fetched, [], 0);
        }
      }
    };

    let therapies = await SubCategoryTherapy.get(filter, null, option, { path: "therapy" });

    // Progress Integration
    let therapyList = therapies.map(therapy => therapy.therapy);
    let therapy_ids = therapyList.map(item => item._id)
    const therapyFilter = { user_id: toObjectId(req['currentUserId']), therapy_id: { $in: [...therapy_ids] } };
    let progressPipeline = await getProgressOfTherapies(therapyFilter)
    const progress = await UserProgress.aggregate(progressPipeline);
    const userlifter = {user_id: toObjectId(req['currentUserId'])}
    let ratings = await ReviewRating.get(userlifter);
    let object = {}, ratingObject = {};
    progress.forEach(therapy => {
      object[therapy.therapy_id] = therapy.completed;
    })
    ratings.forEach(therapy => {
      ratingObject[therapy.therapy_id] = true;
    })
    logger.log(level.info, `integrateProgressWithTherapy Inline progresses:${beautify(object)}`);
    therapies = JSON.parse(JSON.stringify(therapies));

    therapies = therapies.map(subcatTherapy => {
      subcatTherapy['therapy']['completed'] = object[subcatTherapy.therapy_id] || 0;
      subcatTherapy['therapy']['is_review_submitted'] = ratingObject[subcatTherapy.therapy_id] || false;
      return subcatTherapy
    });

    for (const item of therapies) {
      if(item['therapy']['completed'] === 0){
        item['therapy']['completed'] = await getPercentage(item, req['currentUserId'])
      }
    }
    // Progress Integration Finish

    const total = await SubCategoryTherapy.count(filter);

    const subCategoryIds = therapies.map(item => item.sub_category_id);
    const abc = subCategoryIds.flat(1).filter((item, index) => subCategoryIds.flat(1).indexOf(item) === index);
    if (categoryId) {
      const subCategory = (await SubCategory.get({category_id: categoryId})).map(item => item.id);
      abc.sort((a, b) => subCategory.indexOf(a) - subCategory.indexOf(b));
    }
    let array = [];
    abc.forEach(i => {
      const idWiseData = therapies.filter(item => item.sub_category_id.includes(i))
      idWiseData.forEach((item, index) => {
        item.index = index
      });
      array.push(idWiseData)
    });
    const therapiesData = array.flat(1);
     return okResponse(res, messages.record_fetched, therapiesData, total);
  } catch (error) {
    logger.log(level.error, `getTherapiesList Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
}

export const getAllTherapyForAdmin = async (req, res) => {
  try {
    const { query, params } = req;
    const { subCatId = null } = params;
    const { option = {} } = query;
    const { sort = { created_at: -1 } } = option;
    option['sort'] = sort;
    logger.log(level.info, `getAllTherapyForAdmin query=${beautify(query)}, subCatId=${subCatId}`);

    const searchFilter = await parseSearchOptions(option);
    const filter = { is_deleted: false};
    if (subCatId){
      filter['sub_category_id'] = toObjectId(subCatId);
      
      const notExist = await returnOnNotExist(SubCategory, { _id: subCatId, ...deletedCondition }, res, "SubCategory", messages.not_exist.replace("{dynamic}", "SubCategory"));
      if (notExist) return;
    } 
    
    const {pipeline} = await getAllTherapyList(filter,option,searchFilter);
    const getAllTherapyData = await SubCategoryTherapy.aggregate(pipeline);
    let count = await getAllTherapyData.length;

    return okResponse(res, messages.record_fetched, getAllTherapyData, count);
  } catch (error) {
    logger.log(level.error, `getTherapiesList Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
}

async function integrateProgressWithTherapy(progress = [], therapies = [], ratings = []) {
  let object = {}, ratingObject = {};
  progress.forEach(therapy => {
    object[therapy.therapy_id] = therapy.completed;
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

const getPercentage = async (subcatTherapy, userId) => {
  const progressFilter = {therapy_id: subcatTherapy.therapy_id, resource_id: null, user_id: userId}
  const isProgressExist = await UserProgress.get(progressFilter);
  let number = 0;
  if (isProgressExist.length) {
    number = isProgressExist[0].progress_percent
  }
  return number
};

const getImageLink = async (item) => {
  return await getSignedUrl(process.env.Aws_Bucket_Name, item);
};