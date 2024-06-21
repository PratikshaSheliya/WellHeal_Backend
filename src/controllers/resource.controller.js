import HTTPStatus from "http-status";
import Path from "path";

import { logger, level } from "../config/logger.js";
import messages from "../shared/constant/messages.const.js";
import Resource from "../models/resource.model.js";
import Therapy from "../models/therapy.model.js";
import Favorite from "../models/favorite.model.js";
import ResourceType from "../models/resource_type.model.js";
import TherapyResources from "../models/therapy_resources.model.js";
import { internalServerError, beautify, toObjectId, generateRandomString, okResponse, badRequestError, paramMissingError, parseSearchOptions, okResponseTotalCount } from "../shared/utils/utility.js";
import { AUDIO_VIDEO_EXTENSIONS, FAVORITE_CONTENT_TYPE, IMAGE_EXTENSIONS, INTRO_VIDEO_FOR, RESOURCE_FORMAT, VIDEO_EXTENSIONS } from "../shared/constant/types.const.js";
import { getResourceByTherapyIdPipeline, getResourceForSubCategoryPipeline, getResourceForAffirmationPipeline, getAffirmationSubcategoryListPipeline } from "../shared/pipeline/resource.pipeline.js";
import { getSignedUrl, uploadFileToS3 } from "../shared/services/file-upload/aws-s3.service.js";
import IntroVideos from "../models/intro_videos.model.js";
import Category from "../models/category.model.js";
import SubCategory from "../models/sub_category.model.js";
import UserProgress from "../models/user_progress.model.js";
import SubCategoryTherapies from "../models/sub_category_therapies.model.js";
import { returnOnExist, returnOnNotExist } from "../shared/services/database/query.service.js";
import ReviewRating from "../models/review_rating.model.js";
import SubCategoryResource from "../models/sub_category_resource.model.js";
import SubCategoryTherapy from "../models/sub_category_therapies.model.js";
import { getTherapyWithProgress } from "../shared/pipeline/therapy.pipeline.js";
import AffirmationResource from "../models/affirmation_resource.model.js";

const deletedCondition = { is_deleted: false };

export const makeFavoriteAndUnfavorite = async (req, res) => {
  try {
    const { params, query } = req;
    const { type = FAVORITE_CONTENT_TYPE.THERAPY } = query;
    const { id } = params;

    logger.log(level.error, `makeFavoriteAndUnfavorite content_type: ${type} favourite_id=${id}`);

    let filter = { _id: id, status: 1, ...deletedCondition };
    let payload = {
      user_id: req['currentUserId'],
      favourite_id: id,
      model_type: FAVORITE_CONTENT_TYPE[type],
      content_type: type
    }
    logger.log(level.info, `req.headers: userid = ${req['currentUserId']}`);
    let modelName = Therapy;
    var idType = FAVORITE_CONTENT_TYPE[type];
    switch (Number(type)) {
      case FAVORITE_CONTENT_TYPE.THERAPY:
        modelName = Therapy;
        break;
      case FAVORITE_CONTENT_TYPE.RESOURCE:
        modelName = Resource;
        break;
    }

    const notExist = await returnOnNotExist(modelName, filter, res, idType, messages.not_exist.replace("{dynamic}", idType));
    if (notExist) return;

    let message = messages.favorite.replace("{dynamic}", type ? "Resource" : "Category");
    const isInFavorite = await Favorite.isExist(payload);
    if (isInFavorite) {
      await Favorite.delete(payload);
      message = message.replace("{action}", "Removed From");
    }
    else {
      await Favorite.add(payload);
      message = message.replace("{action}", "Added In");
    }

    return okResponse(res, message);

  } catch (error) {
    logger.log(level.error, `makeFavoriteAndUnfavorite Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
}

export const getResourceTypes = async (req, res) => {
  try {
    const { query, params } = req;

    const { option = {} } = query;
    // const { option = {} } = req.query;
    const { sort = { created_at: -1 } } = option;
    option['sort'] = sort;

    const searchFilter = await parseSearchOptions(option);
    const filter = { ...deletedCondition,...searchFilter };

    const resourceTypes = await ResourceType.get(filter, null, option);
    logger.log(level.info, `getResourceTypes Resource types=${beautify(resourceTypes)}`);

    const count = await resourceTypes.length;
    
    return okResponse(res, messages.record_fetched, resourceTypes, count);
  } catch (error) {
    logger.log(level.error, `getResourceTypes Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
}

export const getResourceTypeForUser = async (req, res) => {
  try {
    const { option = {} } = req.query;

    const resourceTypes = await ResourceType.get(deletedCondition, null, option);
    logger.log(level.info, `getResourceTypes Resource types=${beautify(resourceTypes)}`);

    const total = await ResourceType.count(deletedCondition);

    return okResponse(res, messages.record_fetched, resourceTypes, total);
  } catch (error) {
    logger.log(level.error, `getResourceTypes Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
}

export const createResourceType = async (req, res) => {
  try {
    const { body } = req;
    const { type, sort_index } = body;
    logger.log(level.info, `createResourceType body=${beautify(body)}`);

    const isExist = await returnOnExist(ResourceType, { type }, res, "Resource Type is", messages.already_exist.replace('{dynamic}', "Resource Type"))
    if (isExist) return;

    const resourceType = await ResourceType.add({ type, sort_index });
    if (!resourceType) {
      logger.log(level.info, `createResourceType Error`)
      return badRequestError(res, messages.invalid_input);
    }
    logger.log(level.info, `createResourceType resourceType=${beautify(resourceType)}`);
    return okResponse(res, messages.created.replace("{dynamic}", "Resource Type"), resourceType);
  } catch (error) {
    logger.log(level.error, `createResourceType Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
}

export const updateResourceType = async (req, res) => {
  try {
    const { params, body } = req;
    const { resourceTypeId } = params;
    const { type, sort_index } = body;
    logger.log(level.info, `updateResourceType body=${beautify(body)} \n params=${beautify(params)}`);

    const notExist = await returnOnNotExist(ResourceType, { _id: resourceTypeId }, res, "Resource Type", messages.not_exist.replace("{dynamic}", "Resource Type"));
    if (notExist) return;

    const isExist = await returnOnExist(ResourceType, { type, _id: { $ne: resourceTypeId } }, res, "Resource Type is", messages.already_exist.replace('{dynamic}', "Resource Type"))
    if (isExist) return;

    const payload = {};

    if (type) payload['type'] = type;
    if (sort_index) payload['sort_index'] = sort_index;

    const resourceType = await ResourceType.update({ _id: resourceTypeId }, payload);
    if (!resourceType) {
      logger.log(level.info, `updateResourceType Error`)
      return badRequestError(res, messages.invalid_input);
    }
    logger.log(level.info, `updateResourceType resourceType=${beautify(resourceType)}`);
    return okResponse(res, messages.updated.replace("{dynamic}", "Resource Type"), resourceType);
  } catch (error) {
    logger.log(level.error, `updateResourceType Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
}

export const deleteResourceType = async (req, res) => {
  try {
    const { params } = req;
    const { resourceTypeId } = params;

    logger.log(level.error, `deleteResourceType Params: ${beautify(params)}`);
    const resourceType = await ResourceType.delete({ _id: resourceTypeId });
    if (!resourceType) {
      logger.log(level.info, 'deleteResourceType error')
      return badRequestError(res, messages.invalid_input);
    }

    const resources = await Resource.get({ resource_type_id: resourceTypeId, ...deletedCondition });
    for (const resource of resources) {
      await TherapyResources.update({ resource_id: resource._id, ...deletedCondition }, deletePayload);
      await Resource.updateMany({ content_type: FAVORITE_CONTENT_TYPE.RESOURCE, favourite_id: resource._id, ...deletedCondition }, deletePayload);
    }

    logger.log(level.info, `deleteResourceType resourceType=${beautify(resourceType)}`);
    return okResponse(res, messages.deleted.replace("{dynamic}", "Resource Type"));
  } catch (error) {
    logger.log(level.error, `deleteResourceType Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
}

export const getResourceByType = async (req, res) => {
  try {
    const { query, params } = req
    const { option = {}, subCategoryId = null } = query;
    const { type } = params;

    if (!type) {
      logger.log(level.error, `getResourceByType Error= Resource Type is missing.`);
      return paramMissingError(res, messages.missing_key.replace("{dynamic}", "Type"));
    }

    const filter = { resource_type_id: type, ...deletedCondition }

    if (subCategoryId) {
      const notExist = await returnOnNotExist(SubCategory, { _id: subCategoryId }, res, "Sub Category", messages.not_exist.replace("{dynamic}", "Sub Category"));
      if (notExist) return;
      const subCatTherapyIds = (await SubCategoryTherapies.get({ sub_category_id: subCategoryId, is_deleted: false })).map(elem => elem['therapy_id']);
      const therapyResourceIds = (await TherapyResources.get({ therapy_ids: { $in: subCatTherapyIds } })).map(elem => elem['resource_id']);
      filter['_id'] = { $in: therapyResourceIds };
    }

    let resources = await Resource.get(filter, null, option, { path: "resource_type", select: "type" });
    const total = await Resource.count(filter);

    resources = await Promise.all(resources.map(async elem => {
      elem = JSON.parse(JSON.stringify(elem));
      const resourceProgress = (await UserProgress.get({ resource_id: elem._id, user_id: req['currentUserId'] }))[0];
      elem['spent_time'] = resourceProgress?.spent_time || null
      elem['progress_percent'] = resourceProgress?.progress_percent || null;
      return elem;
    }));

    return okResponse(res, messages.record_fetched, resources, total);
  } catch (error) {
    logger.log(level.error, `getResourceByType Error=${beautify(error.message)}`);
    return internalServerError(res, error)
  }
}

export const getResourceByTherapy = async (req, res) => {
  try {
    const { query, params } = req;
    const { therapyId = null } = params;
    const { option = {}, resource_format = null } = query;
    const { sort = { created_at: -1 } } = option;
    option['sort'] = sort;

    const searchFilter = await parseSearchOptions(option);
    const filter = { ...deletedCondition }

    if (therapyId) filter['therapy_ids'] = { $in: [toObjectId(therapyId)] };
    const optionalFilter = { format: Number(resource_format) }
    const { pipeline } = await getResourceByTherapyIdPipeline(filter, req['currentUserId'], option, optionalFilter, searchFilter);
    let resources = await TherapyResources.aggregate(pipeline);
    const count = await resources.length;

    return okResponse(res, messages.record_fetched, resources, count);
  } catch (error) {
    logger.log(level.error, `getResourceByTherapy Error=${beautify(error.message)}`);
    return internalServerError(res, error)
  }
}

export const createResource = async (req, res) => {
  try {
    const { body, files } = req;
    const { resource_type_id, format, description, therapy_ids, name, is_upcomming = false, how_works_title, how_works_description } = body;
    const { thumbnail, resource: resourceFile } = files;
    var resourceS3Folder = process.env.Aws_Upload_Path_For_Resource, thumbFilePath = null, thumbFileName = null, resourceFilePath = null, resourceFileName = null, thumbS3Location = null, resourceS3Location = null;

    logger.log(level.info, `createResource body=${beautify(body)} Files=${beautify(createFileLogObject(thumbnail, resourceFile))}`);

    if (!thumbnail?.length) {
      logger.log(level.info, 'createResource no thumbnail file selection found error')
      return paramMissingError(res, messages.missing_key.replace("{dynamic}", "Thumbnail"));
    }

    if (is_upcomming == false || is_upcomming == 'false') {
      if (!resourceFile?.length) {
        logger.log(level.info, 'createResource no resource file selection found error')
        return paramMissingError(res, messages.missing_key.replace("{dynamic}", "Resource File"));
      }
    }

    if (thumbnail?.length > 0) {
      thumbFilePath = Path.parse(thumbnail[0].originalname);
      thumbFileName = generateRandomString();
      if (!(Object.values(IMAGE_EXTENSIONS).includes(thumbFilePath.ext))) {
        logger.log(level.info, 'createResource invalid thumbnail file selection error , extention: ' + thumbFilePath.ext)
        return badRequestError(res, messages.invalid_file_selected);
      }
    }

    if (resourceFile?.length > 0) {
      resourceFilePath = Path.parse(resourceFile[0].originalname);
      resourceFileName = generateRandomString();
      logger.log(level.info, `createResource extention:  ${resourceFilePath.ext}, Valid Extentions : ${Object.values(AUDIO_VIDEO_EXTENSIONS)}`)
      if (!(Object.values(AUDIO_VIDEO_EXTENSIONS).includes(resourceFilePath.ext))) {
        logger.log(level.info, `createResource invalid resource file selection error`)
        return badRequestError(res, messages.invalid_file_selected);
      }
    }

    const notExist = await returnOnNotExist(ResourceType, { _id: resource_type_id, ...deletedCondition }, res, "Resource Type", messages.not_exist.replace("{dynamic}", "Resource Type"));
    if (notExist) return;

    let uniqueTherapyIds = await filterExistedTherapies(therapy_ids);
    if (uniqueTherapyIds.length <= 0) {
      return badRequestError(res, messages.not_exist.replace("{dynamic}", "All Therapies"))
    }

    const resource = await Resource.add({ url: "", resource_type_id, name, format, description, status: 1, is_upcomming, how_works_title,how_works_description });
    if (!resource) {
      logger.log(level.info, `createResource Error`)
      return badRequestError(res, messages.invalid_input);
    }


    if (thumbnail?.length > 0) {
      thumbS3Location = `${resourceS3Folder}${resource.id}/thumbnail/${thumbFileName}${thumbFilePath.ext}`;
      uploadFileToS3(process.env.Aws_Bucket_Name, thumbS3Location, thumbnail[0]).then((result, error) => {
        if (!error) {
          Resource.update({ _id: resource._id }, { thumbnail_url: thumbS3Location });
        }
        else {
          logger.log(level.error, `Create Resource: AWS upload Thumbnail Error : ${beautify(error)}`);
        }
      });
    }

    if (resourceFile?.length > 0) {
      resourceS3Location = `${resourceS3Folder}${resource.id}/resource/${resourceFileName}${resourceFilePath.ext}`;
      uploadFileToS3(process.env.Aws_Bucket_Name, resourceS3Location, resourceFile[0]).then((result, error) => {
        if (!error) {
          Resource.update({ _id: resource._id }, { url: resourceS3Location });
        } else {
          logger.log(level.error, `Create Resource: AWS upload File Error : ${beautify(error)}`);
        }
      });
    }

    await TherapyResources.add({ resource_id: resource._id, therapy_ids: [...uniqueTherapyIds] });

    // Used because we updating resource table after uploading file so before that we need to return signed url
    resourceS3Location ? resource.url = await getSignedUrl(process.env.Aws_Bucket_Name, resourceS3Location) : null;
    thumbS3Location ? resource.thumbnail_url = await getSignedUrl(process.env.Aws_Bucket_Name, thumbS3Location) : null;

    logger.log(level.info, `createResource resource=${beautify(resource)}`);
    return okResponse(res, messages.created.replace("{dynamic}", "Resource"), resource);
  } catch (error) {
    logger.log(level.error, `createResource Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
}

export const updateResource = async (req, res) => {
  try {
    const { body, params, files } = req;
    const { resource_type_id, format, description, therapy_ids, name, is_upcomming, how_works_title,how_works_description } = body;
    const { resourceId } = params;
    const { thumbnail = [], resource: resourceFile = [] } = files;
    const filter = { _id: resourceId, ...deletedCondition };
    const resourceS3Folder = process.env.Aws_Upload_Path_For_Resource;
    var thumbFilePath = null, thumbFileName = null, resourceFilePath = null, resourceFileName = null, is_resource_available_in_DB = false;
    logger.log(level.info, `updateResource body=${beautify(body)}  Params=${beautify(params)} Files=${beautify(createFileLogObject(thumbnail, resourceFile))}`);


    const notExist = await returnOnNotExist(Resource, filter, res, "Resource", messages.not_exist.replace("{dynamic}", "Resource"));
    if (notExist) return;

    const [resourcetoBeUpdated] = await Resource.get(filter);
    if (!resourcetoBeUpdated?.url || resourcetoBeUpdated?.url == '' || resourcetoBeUpdated?.url == undefined || resourcetoBeUpdated?.url == null) {
      is_resource_available_in_DB = false;
    } else {
      is_resource_available_in_DB = true;
    }

    if (is_resource_available_in_DB == false) {
      if (!resourceFile?.length) {
        logger.log(level.info, 'updateResource no resource file selection found error')
        return paramMissingError(res, messages.missing_key.replace("{dynamic}", "Resource File"));
      }
    }

    if (thumbnail?.length) {
      thumbFilePath = Path.parse(thumbnail[0].originalname);
      thumbFileName = generateRandomString();
      if (!(Object.values(IMAGE_EXTENSIONS).includes(thumbFilePath.ext))) {
        logger.log(level.info, 'updateResource invalid thumbnail file selection error , extention: ' + thumbFilePath.ext)
        return badRequestError(res, messages.invalid_file_selected);
      }
    }

    if (resourceFile?.length) {
      resourceFilePath = Path.parse(resourceFile[0].originalname);
      resourceFileName = generateRandomString();
      if (!(Object.values(AUDIO_VIDEO_EXTENSIONS).includes(resourceFilePath.ext))) {
        logger.log(level.info, `updateResource invalid resource file selection error`)
        return badRequestError(res, messages.invalid_file_selected);
      }
    }

    let uniqueTherapyIds = [];
    if (therapy_ids?.length > 0) {
      uniqueTherapyIds = await filterExistedTherapies(therapy_ids);
      if (uniqueTherapyIds.length <= 0) {
        return badRequestError(res, messages.not_exist.replace("{dynamic}", "All Therapies"))
      }
    }

    const payload = {};

    if (resource_type_id) {
      const therapyTypeNotExist = await returnOnNotExist(ResourceType, { _id: resource_type_id, ...deletedCondition }, res, "Resource Type", messages.not_exist.replace("{dynamic}", "Resource Type"));
      if (therapyTypeNotExist) return;
      payload['resource_type_id'] = resource_type_id;
    }

    if ('format' in body) payload['format'] = format;
    if (description) payload['description'] = description;
    if (name) payload['name'] = name;
    if (is_upcomming != undefined && is_upcomming != null) payload['is_upcomming'] = is_upcomming;
    if (how_works_title) payload['how_works_title'] = how_works_title;
    if (how_works_description) payload['how_works_description'] = how_works_description;

    logger.log(level.info, `updateResource payload=${beautify(payload)}`);
    const resource = await Resource.update(filter, payload);
    if (!resource) {
      logger.log(level.info, `updateResource Error`)
      return badRequestError(res, invalid_input);
    }

    if (thumbFilePath) {
      const thumbS3Location = `${resourceS3Folder}${resourceId}/thumbnail/${thumbFileName}${thumbFilePath.ext}`;
      uploadFileToS3(process.env.Aws_Bucket_Name, thumbS3Location, thumbnail[0]).then((result, error) => {
        if (!error) {
          Resource.update({ _id: resourceId }, { thumbnail_url: thumbS3Location });
        } else {
          logger.log(level.error, `Update Resource: AWS upload Thumbnail Error : ${beautify(error)}`);
        }
      });
      // We required this because signed URL should be return before update in aws.
      resource.thumbnail_url = await getSignedUrl(process.env.Aws_Bucket_Name, thumbS3Location);
    }

    if (resourceFilePath) {
      const resourceS3Location = `${resourceS3Folder}${resource.id}/resource/${resourceFileName}${resourceFilePath.ext}`;
      uploadFileToS3(process.env.Aws_Bucket_Name, resourceS3Location, resourceFile[0]).then((result, error) => {
        if (!error) {
          Resource.update({ _id: resourceId }, { url: resourceS3Location });
        } else {
          logger.log(level.error, `Update Resource: AWS upload File Error : ${beautify(error)}`);
        }
      });
      // We required this because signed URL should be return before update in aws.
      resource.url = await getSignedUrl(process.env.Aws_Bucket_Name, resourceS3Location);
    }

    if (uniqueTherapyIds.length > 0) await TherapyResources.update({ resource_id: resourceId, ...deletedCondition }, { therapy_ids: [...uniqueTherapyIds] });

    logger.log(level.info, `updateResource resource=${beautify(resource)}`);
    return okResponse(res, messages.updated.replace("{dynamic}", "Resource"), resource);

  } catch (error) {
    logger.log(level.error, `updateResource Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
}

export const deleteResource = async (req, res) => {
  try {
    const { params } = req;
    const { resourceId } = params;
    const deletePayload = { is_deleted: true, deleted_at: new Date().toISOString() };

    logger.log(level.error, `deleteResource Params: ${beautify(params)}`);
    const resource = await Resource.update({ _id: resourceId, ...deletedCondition }, deletePayload);
    if (!resource) {
      logger.log(level.info, 'deleteResource error')
      return badRequestError(res, messages.invalid_input);
    }

    await TherapyResources.update({ resource_id: resourceId, ...deletedCondition }, deletePayload);
    await SubCategoryResource.update({ resource_id: toObjectId(resourceId), ...deletedCondition }, deletePayload);
    await IntroVideos.update({ resource_id: toObjectId(resourceId), ...deletedCondition }, deletePayload)
    await Favorite.update({ content_type: FAVORITE_CONTENT_TYPE.RESOURCE, favourite_id: resource._id, ...deletedCondition }, deletePayload);

    logger.log(level.info, `deleteResource resource=${beautify(resource)}`);
    return okResponse(res, messages.deleted.replace("{dynamic}", "Resource"));
  } catch (error) {
    logger.log(level.error, `deleteResource Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
}

export const linkResourceToTherapy = async (req, res) => {
  try {
    const { params, body } = req;
    const { resourceId } = params;
    const { therapy_ids } = body;

    logger.log(level.info, `linkResourceToTherapy body=${beautify(body)} \n params=${beautify(params)}`);

    const notExist = await returnOnNotExist(Resource, { _id: resourceId, ...deletedCondition }, res, "Resource", messages.not_exist.replace("{dynamic}", "Resource"));
    if (notExist) return;

    const uniqueTherapyIds = [...new Set(therapy_ids)];
    const therapyCount = await Therapy.count({ _id: { $in: uniqueTherapyIds }, ...deletedCondition });
    if (therapyCount != uniqueTherapyIds.length) {
      logger.log(level.info, 'linkResourceToTherapy therapy not exist error')
      return badRequestError(res, messages.invalid_input);
    }

    let therapyIds = uniqueTherapyIds;

    let therapyResources = await TherapyResources.get({ resource_id: resourceId, ...deletedCondition });
    if (therapyResources.length) {
      const temp = therapyResources[0].therapy_ids.length ? therapyResources[0].therapy_ids.toString().split(",") : [];
      therapyIds = [...new Set([...therapyIds, ...temp])];
    }

    await TherapyResources.update({ resource_id: resourceId, ...deletedCondition }, { therapy_ids: therapyIds });

    therapyResources = await TherapyResources.get({ resource_id: resourceId, ...deletedCondition }, null, null, { path: 'therapy' });

    logger.log(level.info, `linkResourceToTherapy therapy resources=${beautify(therapyResources)}`);
    return okResponse(res, messages.updated.replace("{dynamic}", "Resource Therapy"), therapyResources);
  } catch (error) {
    logger.log(level.error, `linkResourceToTherapy Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
}

export const unlinkResourceToTherapy = async (req, res) => {
  try {
    const { params, body } = req;
    const { resourceId } = params;
    const { therapy_ids } = body;

    logger.log(level.info, `unlinkResourceToTherapy body=${beautify(body)} \n params=${beautify(params)}`);
    const notExist = await returnOnNotExist(Resource, { _id: resourceId, ...deletedCondition }, res, "Resource", messages.not_exist.replace("{dynamic}", "Resource"));
    if (notExist) return;

    const uniqueTherapyIds = [...new Set(therapy_ids)];
    const therapyCount = await Therapy.count({ _id: { $in: uniqueTherapyIds }, ...deletedCondition });
    if (therapyCount != uniqueTherapyIds.length) {
      logger.log(level.info, 'unlinkResourceToTherapy therapy not exist error')
      return badRequestError(res, HTTPStatus.invalid_input);
    }

    await TherapyResources.update({ resource_id: resourceId, ...deletedCondition }, { $pull: { therapy_ids: { $in: uniqueTherapyIds } } });

    let therapyResources = await TherapyResources.get({ resource_id: resourceId, ...deletedCondition }, null, null, { path: 'therapy' });

    logger.log(level.info, `unlinkResourceToTherapy therapy resources=${beautify(therapyResources)}`);
    return okResponse(res, messages.updated.replace("{dynamic}", "Resource Therapy"), therapyResources);
  } catch (error) {
    logger.log(level.error, `unlinkResourceToTherapy Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
}

export const createIntroVideo = async (req, res) => {
  try {
    const { body, files } = req
    var { name, description, duration, category_id, sub_category_id, content_type } = body;
    const { thumbnail = [], resource: resourceFile = [] } = files;

    logger.log(level.info, `createIntroVideo body=${beautify(body)} Files=${beautify(createFileLogObject(thumbnail, resourceFile))}`);

    if (content_type == INTRO_VIDEO_FOR.APP) {
      const isExist = await returnOnExist(IntroVideos, { content_type, ...deletedCondition }, res, "Intro Video For Application ", messages.already_exist.replace('{dynamic}', "Intro Video"))
      if (isExist) return;
    }

    if (content_type == INTRO_VIDEO_FOR.CATEGORY) {
      if (!category_id) {
        logger.log(level.info, 'createIntroVideo Category id missing error')
        return paramMissingError(res, messages.missing_key.replace("{dynamic}", "Category ID"));
      } else {
        const notExist = await returnOnNotExist(Category, { _id: toObjectId(category_id), ...deletedCondition }, res, "Category", messages.not_exist.replace("{dynamic}", "Category"));
        if (notExist) return;

        const isExist = await returnOnExist(IntroVideos, { category_id, content_type, ...deletedCondition }, res, "Intro Video For Category ", messages.already_exist.replace('{dynamic}', "Intro Video"))
        if (isExist) return;
      }
    }

    if (content_type == INTRO_VIDEO_FOR.SUBCATEGORY) {
      if (!sub_category_id) {
        logger.log(level.info, 'createIntroVideo Sub Category id missing error')
        return paramMissingError(res, messages.missing_key.replace("{dynamic}", "Sub Category ID"));
      } else {
        const filter = { _id: sub_category_id, ...deletedCondition }
        const notExist = await returnOnNotExist(SubCategory, filter, res, "Sub Category", messages.not_exist.replace("{dynamic}", "Sub Category"));
        if (notExist) return;
        const [sub_category] = await SubCategory.get(filter);
        if (sub_category) {
          category_id = sub_category.category_id
        }
      }
    }

    if (!thumbnail?.length) {
      logger.log(level.info, 'createIntroVideo no thumbnail file selection found error')
      return paramMissingError(res, messages.missing_key.replace("{dynamic}", "Thumbnail"));
    }

    if (!resourceFile?.length) {
      logger.log(level.info, 'createIntroVideo no resource file selection found error')
      return paramMissingError(res, messages.missing_key.replace("{dynamic}", "Resource File"));
    }

    const resourceS3Folder = process.env.Aws_Upload_Path_For_Intro_Video;
    const thumbFilePath = Path.parse(thumbnail[0].originalname);
    const thumbFileName = generateRandomString();

    const resourceFilePath = Path.parse(resourceFile[0].originalname);
    const resourceFileName = generateRandomString();

    if (!(Object.values(IMAGE_EXTENSIONS).includes(thumbFilePath.ext))) {
      logger.log(level.info, 'createIntroVideo invalid thumbnail file selection error')
      return badRequestError(res, messages.invalid_file_selected);
    }

    if (!(Object.values(VIDEO_EXTENSIONS).includes(resourceFilePath.ext))) {
      logger.log(level.info, 'createIntroVideo invalid resource file selection error')
      return badRequestError(res, messages.invalid_file_selected);
    }

    const resourcePayload = {
      url: "",
      thumbnail_url: "",
      resource_type_id: null,
      format: RESOURCE_FORMAT.VIDEO,
      description: description,
      name: name,
      duration: duration,
      status: 1
    }

    const resource = await Resource.add(resourcePayload);
    if (!resource) {
      logger.log(level.info, `createIntroVideo Resource Create Error`)
      return badRequestError(res, messages.invalid_input);
    }

    const thumbS3Location = `${resourceS3Folder}${resource.id}/thumbnail/${thumbFileName}${thumbFilePath.ext}`;
    uploadFileToS3(process.env.Aws_Bucket_Name, thumbS3Location, thumbnail[0]).then((result, error) => {
      if (!error) {
        Resource.update({ _id: resource._id }, { thumbnail_url: thumbS3Location });
      } else {
        logger.log(level.error, `Create Intro Video Thumbnail Upload Error : ${beautify(error)}`);
      }
    });

    const resourceS3Location = `${resourceS3Folder}${resource.id}/resource/${resourceFileName}${resourceFilePath.ext}`;
    uploadFileToS3(process.env.Aws_Bucket_Name, resourceS3Location, resourceFile[0]).then((result, error) => {
      if (!error) {
        Resource.update({ _id: resource._id }, { url: resourceS3Location });
      } else {
        logger.log(level.error, `Create Intro Video File Upload Error : ${beautify(error)}`);
      }
    });

    let introVideo = await IntroVideos.add({ name, description, category_id, sub_category_id, content_type, resource_id: resource._id });

    introVideo = (await IntroVideos.get({ _id: introVideo._id }, null, null, { path: 'resource' }))[0];

    // We required this because we are returning response before file uploading so
    introVideo.resource.url = await getSignedUrl(process.env.Aws_Bucket_Name, resourceS3Location);
    introVideo.resource.thumbnail_url = await getSignedUrl(process.env.Aws_Bucket_Name, thumbS3Location);

    logger.log(level.info, `createIntroVideo resource=${beautify(resource)}`);
    return okResponse(res, messages.created.replace("{dynamic}", "Intro Video"), introVideo);
  } catch (error) {
    logger.log(level.error, `createIntroVideo Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
}

export const updateIntroVideo = async (req, res) => {
  try {
    const { body, files, params } = req;
    const { introId } = params;
    const { name, description, duration, category_id, sub_category_id, content_type, status } = body;
    const { thumbnail = [], resource: resourceFile = [] } = files;

    logger.log(level.info, `updateIntroVideo body=${beautify(body)} Params=${params} Files=${beautify(createFileLogObject(thumbnail, resourceFile))}`);

    const isIntroExist = await IntroVideos.get({ _id: introId });
    if (!isIntroExist.length) {
      logger.log(level.info, 'updateIntroVideo intro video not exist error');
      return badRequestError(res, messages.invalid_input);
    }

    if ('content_type' in body && (content_type != isIntroExist[0].content_type)) {
      logger.log(level.info, "updateIntroVideo can't update content type error");
      return badRequestError(res, messages.invalid_input);
    }

    if (content_type == INTRO_VIDEO_FOR.CATEGORY && category_id) {
      const notExist = await returnOnNotExist(Category, { _id: toObjectId(category_id), ...deletedCondition }, res, "Category", messages.not_exist.replace("{dynamic}", "Category"));
      if (notExist) return;
    }

    if (content_type == INTRO_VIDEO_FOR.SUBCATEGORY && sub_category_id) {
      const notExist = await returnOnNotExist(SubCategory, { _id: sub_category_id, ...deletedCondition }, res, "Sub Category", messages.not_exist.replace("{dynamic}", "Sub Category"));
      if (notExist) return;
    }

    const resourceS3Folder = process.env.Aws_Upload_Path_For_Intro_Video;
    let thumbFilePath, thumbFileName, resourceFilePath, resourceFileName;
    if (thumbnail?.length) {
      thumbFilePath = Path.parse(thumbnail[0].originalname);
      thumbFileName = generateRandomString();

      if (!(Object.values(IMAGE_EXTENSIONS).includes(thumbFilePath.ext))) {
        logger.log(level.info, 'updateIntroVideo invalid thumbnail file selection error')
        return badRequestError(res, messages.invalid_file_selected);
      }
    }

    if (resourceFile?.length) {
      resourceFilePath = Path.parse(resourceFile[0].originalname);
      resourceFileName = generateRandomString();

      if (!(Object.values(VIDEO_EXTENSIONS).includes(resourceFilePath.ext))) {
        logger.log(level.info, 'updateIntroVideo invalid resource file selection error')
        return badRequestError(res, messages.invalid_file_selected);
      }
    }

    const resourcePayload = {
      resource_type_id: null,
      format: RESOURCE_FORMAT.VIDEO
    }

    if (description) resourcePayload['description'] = description;
    if (duration) resourcePayload['duration'] = duration;
    if (name) resourcePayload['name'] = name;
    if ('status' in body) resourcePayload['status'] = status;

    const resource = await Resource.update({ _id: isIntroExist[0].resource_id }, resourcePayload);
    if (!resource) {
      logger.log(level.info, `updateIntroVideo Resource Create Error`)
      return badRequestError(res, messages.invalid_input);
    }

    const updateObj = {};
    if (thumbFileName) {
      const thumbS3Location = `${resourceS3Folder}${resource.id}/thumbnail/${thumbFileName}${thumbFilePath.ext}`;
      uploadFileToS3(process.env.Aws_Bucket_Name, thumbS3Location, thumbnail[0]).then((result, error) => {
        if (!error) {
          Resource.update({ _id: resource._id }, { thumbnail_url: thumbS3Location });
        } else {
          logger.log(level.error, `Update Intro Video Thumbnail Upload Error : ${beautify(error)}`);
        }
      });
      updateObj['thumbnail_url'] = await getSignedUrl(process.env.Aws_Bucket_Name, thumbS3Location);
    }

    if (resourceFileName) {
      const resourceS3Location = `${resourceS3Folder}${resource.id}/resource/${resourceFileName}${resourceFilePath.ext}`;
      uploadFileToS3(process.env.Aws_Bucket_Name, resourceS3Location, resourceFile[0]).then((result, error) => {
        if (!error) {
          Resource.update({ _id: resource._id }, { url: resourceS3Location });
        } else {
          logger.log(level.error, `Update Intro Video Thumbnail Upload Error : ${beautify(error)}`);
        }
      });
      updateObj['url'] = await getSignedUrl(process.env.Aws_Bucket_Name, resourceS3Location);
    }

    await Resource.update({ _id: resource._id }, updateObj);

    let introVideo = await IntroVideos.update({ _id: isIntroExist[0]._id }, { name, description, category_id, sub_category_id, content_type, resource_id: resource._id });

    introVideo = (await IntroVideos.get({ _id: isIntroExist[0]._id }, null, null, { path: 'resource' }))[0];

    if (updateObj['thumbnail_url']) {
      introVideo.resource.thumbnail_url = updateObj['thumbnail_url'];
    }
    if (updateObj['url']) {
      introVideo.resource.url = updateObj['url'];
    }

    logger.log(level.info, `updateIntroVideo resource=${beautify(resource)}`);
    return okResponse(res, messages.updated.replace("{dynamic}", "Intro Video"), introVideo);
  } catch (error) {
    logger.log(level.error, `updateIntroVideo Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
}

export const deleteIntroVideo = async (req, res) => {
  try {
    const { params } = req
    const { introId } = params;
    const deletePayload = { is_deleted: true, deleted_at: new Date().toISOString() };

    logger.log(level.info, `deleteIntroVideo introId=${introId}`);

    const [intro] = await IntroVideos.get({ _id: introId });
    if (intro) {
      await Resource.update({ _id: intro.resource_id }, deletePayload);
    }
    await IntroVideos.update({ _id: introId }, deletePayload);

    return okResponse(res, messages.deleted.replace("{dynamic}", "Intro Video"));

  } catch (error) {
    logger.log(level.error, `createIntroVideo Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
}

export const updateUserResourceProgress = async (req, res) => {
  try {
    const { body } = req;
    const { percentage, resource_id, spent_time, therapy_id, sub_category_id } = body;

    logger.log(level.info, `updateIntroVideo body=${beautify(body)}`);

    if (!therapy_id || !sub_category_id) {
      logger.log(level.info, 'updateIntroVideo missing: therapy_id or sub_category_id')
      return paramMissingError(res, messages.missing_key.replace("{dynamic}", "therapy_id or sub_category_id"));
    }

    const notExist = await returnOnNotExist(Resource, { _id: resource_id, ...deletedCondition }, res, "resource", messages.not_exist.replace("{dynamic}", "Resource"));
    if (notExist) return;

    const therapyNotExist = await returnOnNotExist(Therapy, { _id: therapy_id, ...deletedCondition }, res, "Therapy", messages.not_exist.replace("{dynamic}", "Therapy"));
    if (therapyNotExist) return;

    const subcatNotExist = await returnOnNotExist(SubCategory, { _id: sub_category_id, ...deletedCondition }, res, "Sub Category", messages.not_exist.replace("{dynamic}", "Sub Category"));
    if (subcatNotExist) return;

    const isNotTherapyFromCorrectSubCategory = await returnOnNotExist(SubCategoryTherapy, { therapy_id, sub_category_id, ...deletedCondition }, res, "Therapy on Sub Category", messages.invalid_sub_category);
    if (isNotTherapyFromCorrectSubCategory) return;

    const isNotResourceFromCorrectTherapy = await returnOnNotExist(TherapyResources, { resource_id, therapy_ids: therapy_id, ...deletedCondition }, res, "Resource on Therapy", messages.invalid_therapy);
    if (isNotResourceFromCorrectTherapy) return;


    if (percentage > 100 || percentage < 0) {
      logger.log(level.info, 'updateUserResourceProgress invalid progress');
      return badRequestError(res, messages.invalid_key.replace("{dynamic}", "Percentage should be between 0 and 100"));
    }

    const timeSpent = spent_time.split(":");
    if (timeSpent.length != 3) {
      logger.log(level.info, 'updateUserResourceProgress invalid spent time passed error');
      return badRequestError(res, messages.invalid_key.replace("{dynamic}", "Spent Time. Expected Fromat :  `hh:mm:ss` "));
    }

    const isResourceInTherapy = await TherapyResources.get({ resource_id, ...deletedCondition });
    if (!isResourceInTherapy) {
      logger.log(level.info, 'updateUserResourceProgress resource not linked with any therapy error');
      return badRequestError(res, messages.resource_not_linked_with_any_therapy);
    }

    const payload = {
      therapy_id,
      sub_category_id,
      resource_id,
      user_id: req['currentUserId'],
      progress_percent: percentage,
      spent_time
    }

    const filter = { therapy_id, sub_category_id, resource_id, user_id: payload.user_id }
    const isProgressExist = await UserProgress.get(filter);
    if (isProgressExist.length) {
      if (+percentage < +isProgressExist[0].progress_percent) {
        logger.log(level.info, 'updateUserResourceProgress invalid progress percent error');
        return badRequestError(res, messages.invalid_key.replace("{dynamic}", `You Can't Reverse Your Progress. Current progress: ${+isProgressExist[0].progress_percent}`));
      }
      const existSpentTime = isProgressExist[0].spent_time.split(":");
      if (+timeSpent[0] < +existSpentTime[0]) {
        logger.log(level.info, 'updateUserResourceProgress invalid hours in time spent error');
        return badRequestError(res, messages.invalid_key.replace("{dynamic}", `You Can't Reverse Your Progress. Current Hours: ${+existSpentTime[0]}`));
      }

      if (+timeSpent[1] > 60) {
        if (+timeSpent[1] < +existSpentTime[1]) {
          logger.log(level.info, 'updateUserResourceProgress invalid minute in time spent error');
          return badRequestError(res, messages.invalid_key.replace("{dynamic}", `You Can't Reverse Your Progress. Current Minutes: ${+existSpentTime[1]}`));
        }
        logger.log(level.info, 'updateUserResourceProgress more than 60 minute passed in time spent error');
        return badRequestError(res, messages.invalid_key.replace("{dynamic}", `Minutes Can Not Be More Than 60.`));
      }

      if (+timeSpent[2] > 60) {
        if (+timeSpent[2] < +existSpentTime[2]) {
          logger.log(level.info, 'updateUserResourceProgress invalid seconds in time spent error');
          return badRequestError(res, messages.invalid_key.replace("{dynamic}", `You Can't Reverse Your Progress. Current Minutes: ${+existSpentTime[2]}`));
        }
        logger.log(level.info, 'updateUserResourceProgress more than 60 seconds passed in time spent error');
        return badRequestError(res, messages.invalid_key.replace("{dynamic}", `Seconds Can Not Be More Than 60.`));
      }

      const updatePayload = { progress_percent: percentage, spent_time };

      await UserProgress.update(filter, updatePayload);


      const option = {}, is_completed= false;
      logger.log(level.info, `getUserTherapiesWithProgress option=${beautify(option)}`);
  
      var filterData = { user_id: toObjectId(req['currentUserId']) }
      if (sub_category_id) {
        filterData = { ...filterData, sub_category_id: { $in: [sub_category_id] } }
      }
      const { pipeline, countPipeline } = await getTherapyWithProgress(filterData, option, is_completed);
      let therapy = await UserProgress.aggregate(pipeline);
      let count = await UserProgress.aggregate(countPipeline);
      logger.log(level.info, 'updateUserResourceProgress exist progress updated.');
    } else {
      logger.log(level.info, 'updateUserResourceProgress new progress added.');
      await UserProgress.add(payload);

      const option = {}, is_completed= false;
      logger.log(level.info, `getUserTherapiesWithProgress option=${beautify(option)}`);
  
      var filterData = { user_id: toObjectId(req['currentUserId']) }
      if (sub_category_id) {
        filterData = { ...filterData, sub_category_id: { $in: [sub_category_id] } }
      }
      const { pipeline, countPipeline } = await getTherapyWithProgress(filterData, option, is_completed);
      let therapy = await UserProgress.aggregate(pipeline);
      let count = await UserProgress.aggregate(countPipeline);
    }
    return okResponse(res, messages.progress_updated);

  } catch (error) {
    logger.log(level.error, `updateUserResourceProgress Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
}

export const addResourceReviewRating = async (req, res) => {
  try {
    const { body } = req;
    const { rating, review = null, resourceId } = body;

    logger.log(level.info, `addResourceReviewRating body=${beautify(body)}`);

    const notExist = await returnOnNotExist(Resource, { _id: resourceId }, res, "Resource", messages.not_exist.replace("{dynamic}", "Resource"));
    if (notExist) return;

    if (rating < 0 || rating > 5) {
      logger.log(level.info, 'addResourceReviewRating invalid rating number error');
      return badRequestError(res, messages.invalid_input);
    }

    const resourceProgressNotExist = await returnOnNotExist(UserProgress, { user_id: req['currentUserId'], resource_id: resourceId, progress_percent: 100 }, res, "Resource Progress", messages.not_exist.replace("{dynamic}", "Resource Progress"));
    if (resourceProgressNotExist) return;

    await ReviewRating.add({ user_id: req['currentUserId'], rating, review, resource_id: resourceId, therapy_id: null });

    return okResponse(res, messages.rating_added.replace("{dynamic}", "Resource"));

  } catch (error) {
    logger.log(level.error, `addResourceReviewRating Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
}

export const getResourceReviewRatings = async (req, res) => {
  try {
    const { params, query } = req;
    const { resourceId } = params;
    const { option = {} } = query;

    logger.log(level.info, `getResourceReviewRatings params=${beautify(params)}`);

    
    const reviewRatings = await ReviewRating.get({ resource_id: resourceId }, null, option);

    const total = await ReviewRating.count({ resource_id: resourceId });

    return okResponse(res, messages.record_fetched, reviewRatings, total);

  } catch (error) {
    logger.log(level.error, `getResourceReviewRatings Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
}

export const createResourceForSubCategory = async (req, res) => {
  try {
    const { body, files } = req;
    const { sub_category_id, name, description, duration, format, resource_type_id, how_works_title, how_works_description } = body;
    const { thumbnail, resource: resourceFile } = files;

    logger.log(level.info, `createResourceForSubCategory body=${beautify(body)} Files=${beautify(createFileLogObject(thumbnail, resourceFile))}`);

    if (!thumbnail?.length) {
      logger.log(level.info, 'createResourceForSubCategory no thumbnail file selection found error')
      return paramMissingError(res, messages.missing_key.replace("{dynamic}", "Thumbnail"));
    }

    if (!resourceFile?.length) {
      logger.log(level.info, 'createResourceForSubCategory no resource file selection found error')
      return paramMissingError(res, messages.missing_key.replace("{dynamic}", "Resource File"));
    }

    const resourceS3Folder = process.env.Aws_Upload_Path_For_Resource;

    const thumbFilePath = Path.parse(thumbnail[0].originalname);
    const thumbFileName = generateRandomString();

    const resourceFilePath = Path.parse(resourceFile[0].originalname);
    const resourceFileName = generateRandomString();

    if (!(Object.values(IMAGE_EXTENSIONS).includes(thumbFilePath.ext))) {
      logger.log(level.info, 'createResourceForSubCategory invalid thumbnail file selection error')
      return badRequestError(res, messages.invalid_file_selected);
    }

    if (!(Object.values(AUDIO_VIDEO_EXTENSIONS).includes(resourceFilePath.ext))) {
      logger.log(level.info, 'createResourceForSubCategory invalid resource file selection error')
      return badRequestError(res, messages.invalid_file_selected);
    }

    const notExist = await returnOnNotExist(ResourceType, { _id: resource_type_id, ...deletedCondition }, res, "Resource Type", messages.not_exist.replace("{dynamic}", "Resource Type"));
    if (notExist) return;

    const subCategoryNotExist = await returnOnNotExist(SubCategory, { _id: sub_category_id, ...deletedCondition }, res, "Sub Category", messages.not_exist.replace("{dynamic}", "Sub Category"));
    if (subCategoryNotExist) return;

    const resource = await Resource.add({ url: "", resource_type_id, name, format, description, duration, status: 1 , how_works_title, how_works_description });
    if (!resource) {
      logger.log(level.info, `createResourceForSubCategory Error`)
      return badRequestError(res, messages.invalid_input);
    }

    const thumbS3Location = `${resourceS3Folder}${resource.id}/thumbnail/${thumbFileName}${thumbFilePath.ext}`;
    uploadFileToS3(process.env.Aws_Bucket_Name, thumbS3Location, thumbnail[0]).then((result, error) => {
      if (!error) {
        Resource.update({ _id: resource._id }, { thumbnail_url: thumbS3Location });
      }
      else {
        logger.log(level.error, `createResourceForSubCategory: AWS upload Thumbnail Error : ${beautify(error)}`);
      }
    });

    const resourceS3Location = `${resourceS3Folder}${resource.id}/resource/${resourceFileName}${resourceFilePath.ext}`;
    uploadFileToS3(process.env.Aws_Bucket_Name, resourceS3Location, resourceFile[0]).then((result, error) => {
      if (!error) {
        Resource.update({ _id: resource._id }, { url: resourceS3Location });
      } else {
        logger.log(level.error, `createResourceForSubCategory: AWS upload File Error : ${beautify(error)}`);
      }
    });

    await SubCategoryResource.add({ resource_id: resource._id, sub_category_id: [sub_category_id] });
    // Used because we updating resource table after uploading file so before that we need to return signed url
    resource.url = await getSignedUrl(process.env.Aws_Bucket_Name, resourceS3Location);
    resource.thumbnail_url = await getSignedUrl(process.env.Aws_Bucket_Name, thumbS3Location);

    logger.log(level.info, `createResource resource=${beautify(resource)}`);
    return okResponse(res, messages.created.replace("{dynamic}", "Resource"), resource);
  } catch (error) {
    logger.log(level.error, `createResource Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
}

export const updateResourceForSubCategory = async (req, res) => {
  try {
    const { body, params, files } = req;
    const { resource_type_id, name, description, duration, format, how_works_title, how_works_description } = body;
    const { resourceId } = params;
    const { thumbnail = [], resource: resourceFile = [] } = files;

    logger.log(level.info, `updateResourceForSubCategory body=${beautify(body)}  Params=${beautify(params)} Files=${beautify(createFileLogObject(thumbnail, resourceFile))}`);

    const resourceS3Folder = process.env.Aws_Upload_Path_For_Resource;

    let thumbFilePath = null, thumbFileName = null, resourceFilePath = null, resourceFileName = null;

    if (thumbnail?.length) {
      thumbFilePath = Path.parse(thumbnail[0].originalname);
      thumbFileName = generateRandomString();
    }

    if (resourceFile?.length) {
      resourceFilePath = Path.parse(resourceFile[0].originalname);
      resourceFileName = generateRandomString();
    }

    const notExist = await returnOnNotExist(Resource, { _id: resourceId, ...deletedCondition }, res, "Resource", messages.not_exist.replace("{dynamic}", "Resource"));
    if (notExist) return;

    const payload = {};

    if (resource_type_id) {
      const therapyTypeNotExist = await returnOnNotExist(ResourceType, { _id: resource_type_id, ...deletedCondition }, res, "Resource Type", messages.not_exist.replace("{dynamic}", "Resource Type"));
      if (therapyTypeNotExist) return;
      payload['resource_type_id'] = resource_type_id;
    }

    if ('format' in body) payload['format'] = format;
    if (description) payload['description'] = description;
    if (duration) payload['duration'] = duration;
    if (name) payload['name'] = name;
    if (how_works_title) payload['how_works_title'] = how_works_title;
    if (how_works_description) payload['how_works_description'] = how_works_description;

    logger.log(level.info, `updateResourceForSubCategory payload=${beautify(payload)}`);
    const resource = await Resource.update({ _id: resourceId, ...deletedCondition }, payload);
    if (!resource) {
      logger.log(level.info, `updateResourceForSubCategory Error`)
      return badRequestError(res, invalid_input);
    }

    if (thumbFilePath) {
      const thumbS3Location = `${resourceS3Folder}${resource.id}/thumbnail/${thumbFileName}${thumbFilePath.ext}`;
      uploadFileToS3(process.env.Aws_Bucket_Name, thumbS3Location, thumbnail[0]).then((result, error) => {
        if (!error) {
          Resource.update({ _id: resource.id }, { thumbnail_url: thumbS3Location });
        } else {
          logger.log(level.error, `Update Resource: AWS upload Thumbnail Error : ${beautify(error)}`);
        }
      });
      // We required this because signed URL should be return before update in aws.
      resource.thumbnail_url = await getSignedUrl(process.env.Aws_Bucket_Name, thumbS3Location);
    }

    if (resourceFilePath) {
      const resourceS3Location = `${resourceS3Folder}${resource.id}/resource/${resourceFileName}${resourceFilePath.ext}`;
      uploadFileToS3(process.env.Aws_Bucket_Name, resourceS3Location, resourceFile[0]).then((result, error) => {
        if (!error) {
          Resource.update({ _id: resource.id }, { url: resourceS3Location });
        } else {
          logger.log(level.error, `Update Resource: AWS upload File Error : ${beautify(error)}`);
        }
      });
      // We required this because signed URL should be return before update in aws.
      resource.url = await getSignedUrl(process.env.Aws_Bucket_Name, resourceS3Location);
    }

    logger.log(level.info, `updateResource resource=${beautify(resource)}`);
    return okResponse(res, messages.updated.replace("{dynamic}", "Resource"), resource);

  } catch (error) {
    logger.log(level.error, `updateResource Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
}

export const deleteResourceForSubCategory = async (req, res) => {
  try {
    const { params } = req;
    const { resourceId } = params;

    logger.log(level.info, `deleteResourceForSubCategory params=${beautify(params)}`);

    const isSubCatResourceNotExist = await returnOnNotExist(SubCategoryResource, { resource_id: toObjectId(resourceId), ...deletedCondition }, res, "Sub Category Resource", messages.not_exist.replace("{dynamic}", "Sub Category Resource"));
    if (isSubCatResourceNotExist) return;

    const isResourceNotExist = await returnOnNotExist(Resource, { _id: toObjectId(resourceId), ...deletedCondition }, res, "Resource", messages.not_exist.replace("{dynamic}", "Resource"));
    if (isResourceNotExist) return;

    await SubCategoryResource.update({ resource_id: toObjectId(resourceId) }, { is_deleted: true, deleted_at: new Date().toISOString() });
    await Resource.update({ _id: toObjectId(resourceId) }, { is_deleted: true, deleted_at: new Date().toISOString() });

    return okResponse(res, messages.deleted.replace("{dynamic}", "Sub Category Resource"));
  } catch (error) {
    logger.log(level.error, `updateResourceForSubCategory Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
}

export const getResourceForSubCategory = async (req, res) => {
  try {
    const { params, query } = req;
    const { subCategoryId = null } = params;
    let { categoryId, resourceTypeId = null } = query;

    logger.log(level.info, `getResourceForSubCategory params=${beautify(params)}`);
    const { option = {} } = query;
    const { sort = { created_at: -1 } } = option;
    option['sort'] = sort;
    
    const searchFilter = await parseSearchOptions(option);
    const filter = { ...deletedCondition };

    if (!categoryId) return paramMissingError(res, messages.missing_key.replace("{dynamic}", "Category Id"));

        if (!Array.isArray(categoryId)) {
          categoryId = JSON.parse(categoryId);
        } else{
          categoryId = [categoryId];
        }

    if (subCategoryId) {
      filter['sub_category_id'] = { $in: [toObjectId(subCategoryId)] }
    } else {
      const sub_categories = (await SubCategory.get({ category_id: { $in:categoryId } })).map(subCat => toObjectId(subCat._id));
      filter['sub_category_id'] = { $in: sub_categories }
    }

    const { pipeline,countPipeline } = await getResourceForSubCategoryPipeline(filter, req['currentUserId'], option, resourceTypeId,searchFilter);
    const resources = await SubCategoryResource.aggregate(pipeline);
    const totalcount = await SubCategoryResource.aggregate(countPipeline);
    // const count =  resources.length;
    return okResponseTotalCount(res, messages.record_fetched, resources,totalcount.length,resources.length)
    // return okResponse(res, messages.record_fetched, resources, , resources.length)
  } catch (error) {
    logger.log(level.error, `getResourceForSubCategory Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
}

export const createResourceForAffirmation = async (req, res) => {
  try {
    const { body, files } = req;
    const { sub_category_id, name, description, duration, format, resource_type_id, how_works_title, how_works_description } = body;
    const { thumbnail, resource: resourceFile } = files;
    logger.log(level.info, `createResourceForAffirmation body=${beautify(body)} Files=${beautify(createFileLogObject(thumbnail, resourceFile))}`);

    if (!thumbnail?.length) {
      logger.log(level.info, 'createResourceForAffirmation no thumbnail file selection found error')
      return paramMissingError(res, messages.missing_key.replace("{dynamic}", "Thumbnail"));
    }

    if (!resourceFile?.length) {
      logger.log(level.info, 'createResourceForAffirmation no resource file selection found error')
      return paramMissingError(res, messages.missing_key.replace("{dynamic}", "Resource File"));
    }

    const resourceS3Folder = process.env.Aws_Upload_Path_For_Resource;

    const thumbFilePath = Path.parse(thumbnail[0].originalname);
    const thumbFileName = generateRandomString();

    const resourceFilePath = Path.parse(resourceFile[0].originalname);
    const resourceFileName = generateRandomString();

    if (!(Object.values(IMAGE_EXTENSIONS).includes(thumbFilePath.ext))) {
      logger.log(level.info, 'createResourceForAffirmation invalid thumbnail file selection error')
      return badRequestError(res, messages.invalid_file_selected);
    }

    if (!(Object.values(AUDIO_VIDEO_EXTENSIONS).includes(resourceFilePath.ext))) {
      logger.log(level.info, 'createResourceForAffirmation invalid resource file selection error')
      return badRequestError(res, messages.invalid_file_selected);
    }

    const notExist = await returnOnNotExist(ResourceType, { _id: resource_type_id, ...deletedCondition }, res, "Resource Type", messages.not_exist.replace("{dynamic}", "Resource Type"));
    if (notExist) return;

    const subCategoryNotExist = await returnOnNotExist(SubCategory, { _id: sub_category_id, ...deletedCondition }, res, "Sub Category", messages.not_exist.replace("{dynamic}", "Sub Category"));
    if (subCategoryNotExist) return;

    const resource = await Resource.add({ url: "", resource_type_id, name, format, description, duration, status: 1 , how_works_title, how_works_description });
    if (!resource) {
      logger.log(level.info, `createResourceForAffirmation Error`)
      return badRequestError(res, messages.invalid_input);
    }

    const thumbS3Location = `${resourceS3Folder}${resource.id}/thumbnail/${thumbFileName}${thumbFilePath.ext}`;
    uploadFileToS3(process.env.Aws_Bucket_Name, thumbS3Location, thumbnail[0]).then((result, error) => {
      if (!error) {
        Resource.update({ _id: resource._id }, { thumbnail_url: thumbS3Location });
      }
      else {
        logger.log(level.error, `createResourceForAffirmation: AWS upload Thumbnail Error : ${beautify(error)}`);
      }
    });

    const resourceS3Location = `${resourceS3Folder}${resource.id}/resource/${resourceFileName}${resourceFilePath.ext}`;
    uploadFileToS3(process.env.Aws_Bucket_Name, resourceS3Location, resourceFile[0]).then((result, error) => {
      if (!error) {
        Resource.update({ _id: resource._id }, { url: resourceS3Location });
      } else {
        logger.log(level.error, `createResourceForAffirmation: AWS upload File Error : ${beautify(error)}`);
      }
    });

    await AffirmationResource.add({ resource_id: resource._id, sub_category_id: [sub_category_id] });
    // Used because we updating resource table after uploading file so before that we need to return signed url
    resource.url = await getSignedUrl(process.env.Aws_Bucket_Name, resourceS3Location);
    resource.thumbnail_url = await getSignedUrl(process.env.Aws_Bucket_Name, thumbS3Location);

    logger.log(level.info, `createResource resource=${beautify(resource)}`);
    return okResponse(res, messages.created.replace("{dynamic}", "Affirmation Resource"), resource);
  } catch (error) {
    logger.log(level.error, `createResource Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
}

export const updateResourceForAffirmation = async (req, res) => {
  try {
    const { body, params, files } = req;
    const { resource_type_id, name, description, duration, format, how_works_title, how_works_description } = body;
    const { resourceId } = params;
    const { thumbnail = [], resource: resourceFile = [] } = files;

    logger.log(level.info, `updateResourceForAffirmation body=${beautify(body)}  Params=${beautify(params)} Files=${beautify(createFileLogObject(thumbnail, resourceFile))}`);

    const resourceS3Folder = process.env.Aws_Upload_Path_For_Resource;

    let thumbFilePath = null, thumbFileName = null, resourceFilePath = null, resourceFileName = null;

    if (thumbnail?.length) {
      thumbFilePath = Path.parse(thumbnail[0].originalname);
      thumbFileName = generateRandomString();
    }

    if (resourceFile?.length) {
      resourceFilePath = Path.parse(resourceFile[0].originalname);
      resourceFileName = generateRandomString();
    }

    const notExist = await returnOnNotExist(Resource, { _id: resourceId, ...deletedCondition }, res, "Resource", messages.not_exist.replace("{dynamic}", "Resource"));
    if (notExist) return;

    const payload = {};

    if (resource_type_id) {
      const therapyTypeNotExist = await returnOnNotExist(ResourceType, { _id: resource_type_id, ...deletedCondition }, res, "Resource Type", messages.not_exist.replace("{dynamic}", "Resource Type"));
      if (therapyTypeNotExist) return;
      payload['resource_type_id'] = resource_type_id;
    }

    if ('format' in body) payload['format'] = format;
    if (description) payload['description'] = description;
    if (duration) payload['duration'] = duration;
    if (name) payload['name'] = name;
    if (how_works_title) payload['how_works_title'] = how_works_title;
    if (how_works_description) payload['how_works_description'] = how_works_description;

    logger.log(level.info, `updateResourceForAffirmation payload=${beautify(payload)}`);
    const resource = await Resource.update({ _id: resourceId, ...deletedCondition }, payload);
    if (!resource) {
      logger.log(level.info, `updateResourceForAffirmation Error`)
      return badRequestError(res, invalid_input);
    }

    if (thumbFilePath) {
      const thumbS3Location = `${resourceS3Folder}${resource.id}/thumbnail/${thumbFileName}${thumbFilePath.ext}`;
      uploadFileToS3(process.env.Aws_Bucket_Name, thumbS3Location, thumbnail[0]).then((result, error) => {
        if (!error) {
          Resource.update({ _id: resource.id }, { thumbnail_url: thumbS3Location });
        } else {
          logger.log(level.error, `Update Resource: AWS upload Thumbnail Error : ${beautify(error)}`);
        }
      });
      // We required this because signed URL should be return before update in aws.
      resource.thumbnail_url = await getSignedUrl(process.env.Aws_Bucket_Name, thumbS3Location);
    }

    if (resourceFilePath) {
      const resourceS3Location = `${resourceS3Folder}${resource.id}/resource/${resourceFileName}${resourceFilePath.ext}`;
      uploadFileToS3(process.env.Aws_Bucket_Name, resourceS3Location, resourceFile[0]).then((result, error) => {
        if (!error) {
          Resource.update({ _id: resource.id }, { url: resourceS3Location });
        } else {
          logger.log(level.error, `Update Resource: AWS upload File Error : ${beautify(error)}`);
        }
      });
      // We required this because signed URL should be return before update in aws.
      resource.url = await getSignedUrl(process.env.Aws_Bucket_Name, resourceS3Location);
    }

    logger.log(level.info, `updateResource resource=${beautify(resource)}`);
    return okResponse(res, messages.updated.replace("{dynamic}", "Resource"), resource);

  } catch (error) {
    logger.log(level.error, `updateResource Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
}

export const deleteResourceForAffirmation = async (req, res) => {
  try {
    const { params } = req;
    const { resourceId } = params;

    logger.log(level.info, `deleteResourceForAffirmation params=${beautify(params)}`);

    const isAffirmationResourceNotExist = await returnOnNotExist(AffirmationResource, { resource_id: toObjectId(resourceId), ...deletedCondition }, res, "Affirmation Resource", messages.not_exist.replace("{dynamic}", "Affirmation Resource"));
    if (isAffirmationResourceNotExist) return;

    const isResourceNotExist = await returnOnNotExist(Resource, { _id: toObjectId(resourceId), ...deletedCondition }, res, "Resource", messages.not_exist.replace("{dynamic}", "Resource"));
    if (isResourceNotExist) return;

    await AffirmationResource.update({ resource_id: toObjectId(resourceId) }, { is_deleted: true, deleted_at: new Date().toISOString() });
    await Resource.update({ _id: toObjectId(resourceId) }, { is_deleted: true, deleted_at: new Date().toISOString() });

    return okResponse(res, messages.deleted.replace("{dynamic}", "Affirmation Resource"));
  } catch (error) {
    logger.log(level.error, `updateResourceForAffirmation Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
}

export const getResourceForAffirmation = async (req, res) => {
  try {
    const { params, query } = req;
    const { subCategoryId = null } = params;
    let  { categoryId, resourceTypeId = null } = query;
    logger.log(level.info, `getResourceForAffirmation params=${beautify(params)}`);
    const { option = {} } = query;
    const { sort = { created_at: -1 } } = option;
    option['sort'] = sort;
    
    const searchFilter = await parseSearchOptions(option);
    const filter = { ...deletedCondition };

    if (!categoryId) return paramMissingError(res, messages.missing_key.replace("{dynamic}", "Category Id"));

        if (!Array.isArray(categoryId)) {
          categoryId = JSON.parse(categoryId);
        } else{
          categoryId = [categoryId];
        }

    if (subCategoryId) {
      filter['sub_category_id'] = { $in: [toObjectId(subCategoryId)] }
    } else {

      const sub_categories = (await SubCategory.get({ category_id: { $in:categoryId } })).map(subCat => toObjectId(subCat._id));
      filter['sub_category_id'] = { $in: sub_categories }
    }

    const { pipeline, countPipeline } = await getResourceForAffirmationPipeline(filter, req['currentUserId'], option, resourceTypeId,searchFilter);
    const resources = await AffirmationResource.aggregate(pipeline);
    const totalcount = await AffirmationResource.aggregate(countPipeline);
    // const count =  resources.length;
    
    return okResponseTotalCount(res, messages.record_fetched, resources,totalcount.length,resources.length)
  } catch (error) {
    logger.log(level.error, `getResourceForAffirmation Error: ${beautify(error.message)}`);
    return internalServerError(res, error);
  }
}

export const getAffirmationSubcategoryList = async (req, res) => {
  try {
      const { params, query } = req;
      const { subCategoryId = null } = params;
      let  { categoryId, resourceTypeId = null } = query;
      logger.log(level.info, `getAffirmationSubcategoryList params=${beautify(params)}`);
      
      const { option = {} } = query;
      const { sort = { created_at: -1 } } = option;
      option['sort'] = sort;
      
      const filter = { ...deletedCondition };

      if (!categoryId) return paramMissingError(res, messages.missing_key.replace("{dynamic}", "Category Id"));

          if (!Array.isArray(categoryId)) {
            categoryId = JSON.parse(categoryId);
          } else{
            categoryId = [categoryId];
          }

      if (subCategoryId) {
        filter['sub_category_id'] = { $in: [toObjectId(subCategoryId)] }
      } else {

        const sub_categories = (await SubCategory.get({ category_id: { $in:categoryId } })).map(subCat => toObjectId(subCat._id));
        filter['sub_category_id'] = { $in: sub_categories }
      }
      const { pipeline ,countPipeline} = await getAffirmationSubcategoryListPipeline(filter, req['currentUserId'], option, resourceTypeId);
      let resources = await AffirmationResource.aggregate(pipeline);

      // Extract unique sub-categories
      let uniqueSubCategories = new Set();

      resources.forEach(subcategorylist => {
      if(subcategorylist.sub_category && subcategorylist.sub_category.length > 0)
        {
          subcategorylist.sub_category.forEach(subCategory =>{
            uniqueSubCategories.add(JSON.stringify(subCategory ))
          })
        }
      });

      // Convert set back to array of unique sub-categories
      const uniqueSubCategoriesArray = Array.from(uniqueSubCategories).map(subCategory => JSON.parse(subCategory));
    return okResponse(res, messages.record_fetched, uniqueSubCategoriesArray)
         
  }catch (error) {
      logger.log(level.error, `getAffirmationSubcategoryList Error: ${beautify(error.message)}`);
      return internalServerError(res, error);
    }
  }


function createFileLogObject(thumbnail, resource) {
  const obj = {
    thumbnail_length: thumbnail?.length || null,
    thumbnail_extention: thumbnail?.length > 0 ? Path.parse(thumbnail[0].originalname).ext : null,
    resource_length: resource?.length || null,
    resource_extention: resource?.length > 0 ? Path.parse(resource[0].originalname).ext : null
  }
  return obj
}

async function filterExistedTherapies(therapy_ids) {
  let uniqueTherapyIds = [...new Set(therapy_ids)];
  logger.log(level.info, `Body.TherapyIds: ${beautify(uniqueTherapyIds)}`);
  let therapies = (await Therapy.get({ _id: { $in: uniqueTherapyIds }, ...deletedCondition })).map(item => item.id);
  logger.log(level.info, `Table.Therapy: ${beautify(therapies)}`);
  uniqueTherapyIds = uniqueTherapyIds.filter(id => { return therapies.indexOf(id) != -1 })
  logger.log(level.info, `Body.TherapyIds After Filter: ${beautify(uniqueTherapyIds)}`);
  return uniqueTherapyIds;
}