import HTTPStatus from "http-status";
import messages from "../shared/constant/messages.const.js";
import Category from "../models/category.model.js";
import SubCategory from "../models/sub_category.model.js";
import { logger, level } from "../config/logger.js";
import { internalServerError, beautify, okResponse, badRequestError, toObjectId, generateRandomString, paramMissingError, parseSearchOptions } from "../shared/utils/utility.js";
import SubCategoryTherapy from "../models/sub_category_therapies.model.js";
import { returnOnExist, returnOnNotExist } from "../shared/services/database/query.service.js";
import { getSubcategoryByCategoryPipeline } from "../shared/pipeline/category.pipeline.js";
import Therapy from "../models/therapy.model.js";
import TherapyResources from "../models/therapy_resources.model.js";
import Resource from "../models/resource.model.js";
import { IMAGE_EXTENSIONS, INTRO_VIDEO_FOR } from "../shared/constant/types.const.js";
import SubCategoryResource from "../models/sub_category_resource.model.js";
import IntroVideos from "../models/intro_videos.model.js";
import { getSignedUrl, uploadFileToS3 } from "../shared/services/file-upload/aws-s3.service.js";
import Path from "path";

const deletedCondition = { is_deleted: false };

export const getCategory = async (req, res) => {
    try {
        const { query, params } = req;
        const { option = {} } = query;
        //const { option = {} } = req.query;
        const { sort = { created_at: -1 } } = option;
        option['sort'] = sort;

        const searchFilter = await parseSearchOptions(option);

        const condition = { ...deletedCondition, ...searchFilter };

        const category = await Category.get(condition, null, option);
        const total = await Category.count(condition);
        return okResponse(res, messages.record_fetched, category, total)

    } catch (error) {
        logger.log(level.error, `getCategory Error: ${beautify(error.message)}`);
        return internalServerError(res, error)
    }
}

export const createCategory = async (req, res) => {
    try {
        logger.log(level.info, `createCategory body=${beautify(req.body)}`)

        const { name } = req.body;

        const isExist = await returnOnExist(Category, { name, ...deletedCondition }, res, "Category is", messages.already_exist.replace('{dynamic}', "Category"))
        if (isExist) return;

        const category = await Category.add({ name });
        if (!category) {
            logger.log(level.info, `createCategory Error`)
            return badRequestError(res, messages.invalid_input, null, HTTPStatus.NOT_FOUND)
        }
        logger.log(level.info, `createCategory category=${beautify(category)}`);
        return okResponse(res, messages.created.replace("{dynamic}", "Category"), category);
    } catch (error) {
        logger.log(level.error, `createCategory Error: ${beautify(error.message)}`);
        return internalServerError(res, error);
    }
}

export const updateCategory = async (req, res) => {
    try {
        const { body, params } = req;
        const { catId } = params;
        const { name = null } = body;
        logger.log(level.info, `updateCategory body=${beautify(body)} \n params=${beautify(params)}`);

        const notExist = await returnOnNotExist(Category, { _id: catId, ...deletedCondition }, res, "Category", messages.not_exist.replace("{dynamic}", "Category"));
        if (notExist) return;

        const isExist = await returnOnExist(Category, { name, _id: { $ne: catId }, ...deletedCondition }, res, "Category is", messages.already_exist.replace('{dynamic}', "Category"))
        if (isExist) return;

        const payload = {};
        if (name) payload['name'] = name;
        if ('status' in body) payload['status'] = status;

        const category = await Category.update({ _id: catId }, payload);
        if (!category) {
            logger.log(level.info, `updateCategory Error`)
            return badRequestError(res, messages.invalid_input)
        }

        logger.log(level.info, `updateCategory category=${beautify(category)}`);
        return okResponse(res, messages.updated.replace("{dynamic}", "Category"), category)
    } catch (error) {
        logger.log(level.error, `updateCategory Error: ${beautify(error.message)}`);
        return internalServerError(res, error);
    }
}

export const deleteCategory = async (req, res) => {
    try {
        const { params } = req;
        const { catId } = params;
        const deletePayload = { is_deleted: true, deleted_at: new Date().toISOString() };

        await Category.update({ _id: catId, ...deletedCondition }, deletePayload);

        const subCategories = await SubCategory.get({ category_id: catId, ...deletedCondition });
        for (const subCategory of subCategories) {
            await SubCategory.update({ _id: subCategory._id, ...deletedCondition }, deletePayload);

            const subCategoryTherapies = await SubCategoryTherapy.get({ sub_category_id: subCategory._id });
            for (const subCatTherapy of subCategoryTherapies) {
                await SubCategoryTherapy.update({ _id: subCatTherapy._id }, { $pull: { sub_category_id: subCategory._id } });
            }
        }
        return okResponse(res, messages.deleted.replace("{dynamic}", "Category"))

    } catch (error) {
        logger.log(level.error, `deleteCategory Error: ${beautify(error.message)}`);
        return internalServerError(res, error);
    }
}

export const getSubCategory = async (req, res) => {
    try {
        const { query, params } = req;
        const { catId = null } = params;
        const { subCatId = null, option = {} } = query;

        const filter = { ...deletedCondition };

        if (subCatId) filter['_id'] = toObjectId(subCatId);

        if (catId) {
            const notExist = await returnOnNotExist(Category, { _id: catId, ...deletedCondition }, res, "Category", messages.not_exist.replace("{dynamic}", "Category"));
            if (notExist) return;
            filter.category_id = toObjectId(catId);
        }

        const { pipeline, countPipeline } = await getSubcategoryByCategoryPipeline(filter, option);
        const subCategory = await SubCategory.aggregate(pipeline);
        const total = await SubCategory.aggregate(countPipeline);
        return okResponse(res, messages.record_fetched, subCategory, total.length);

    } catch (error) {
        logger.log(level.error, `getSubCategory Error: ${beautify(error.message)}`);
        return internalServerError(res, error)
    }
}

export const getSubCategoriesForAdmin = async (req, res) => {
    try {
        const { query, params } = req;
        const { catId = null } = params;
        const { option = {} } = query;
        const { sort = { created_at: -1 } } = option;
        option['sort'] = sort;

        const searchFilter = await parseSearchOptions(option);
        const filter = { ...deletedCondition,...searchFilter };

        if (catId) {
            filter['category_id'] = toObjectId(catId);
            const notExist = await returnOnNotExist(Category, { _id: catId, ...deletedCondition }, res, "Category", messages.not_exist.replace("{dynamic}", "Category"));
            if (notExist) return;
        }
        const { pipeline } = await getSubcategoryByCategoryPipeline(filter, option);
        const subCategory = await SubCategory.aggregate(pipeline);
        const count = await subCategory.length;
        return okResponse(res, messages.record_fetched, subCategory, count);

    } catch (error) {
        logger.log(level.error, `getSubCategory Error: ${beautify(error.message)}`);
        return internalServerError(res, error)
    }
}

export const createSubCategory = async (req, res) => {
    try {
        const { body, files } = req;
        const { file, zoneimage, affirmationzoneimge } = files;
        let filePath3,fileName3,s3Location3;

        let therapyS3Folder = process.env.Aws_Upload_Path_For_Sub_Categories;      

        const { name, sub_category_code, category_id, is_upcomming = false } = body;
        logger.log(level.info, `createSubCategory body=${beautify(body)}`);


        const notExist = await returnOnNotExist(Category, { _id: category_id, ...deletedCondition }, res, "Category", messages.not_exist.replace("{dynamic}", "Category"));
        if (notExist) return;

        const isExist = await returnOnExist(SubCategory, { category_id: category_id, name, ...deletedCondition }, res, "Sub Category Name is", messages.already_exist.replace('{dynamic}', "Sub Category Name"))
        if (isExist) return;

        const hasSubCategoryCode = await returnOnExist(SubCategory, { sub_category_code, ...deletedCondition }, res, "Sub Category Code is", messages.already_exist.replace('{dynamic}', "Sub Category Code"))
        if (hasSubCategoryCode) return;


        if (!file || !zoneimage) {
            logger.log(level.info, 'createSubCategory no file selection found error')
            return paramMissingError(res, messages.missing_key.replace("{dynamic}", "Thumbnail File"));
        }

        const filePath = Path.parse(file[0].originalname);
        const fileName = generateRandomString();

        const filePath2 = Path.parse(zoneimage[0].originalname);
        const fileName2 = generateRandomString();

        if(affirmationzoneimge){
            if(affirmationzoneimge[0]){

                fileName3 = generateRandomString();
                filePath3 = Path.parse(affirmationzoneimge[0].originalname);
                
                if (!(Object.values(IMAGE_EXTENSIONS).includes(filePath3.ext))) {
                    logger.log(level.info, 'createSubCategory invalid affirmationzoneimge file selection error')
                    return badRequestError(res, messages.invalid_file_selected);
                }
            }
        }

        if (!(Object.values(IMAGE_EXTENSIONS).includes(filePath.ext))) {
            logger.log(level.info, 'createSubCategory invalid file selection error')
            return badRequestError(res, messages.invalid_file_selected);
        }

        if (!(Object.values(IMAGE_EXTENSIONS).includes(filePath2.ext))) {
            logger.log(level.info, 'createSubCategory invalid file selection error')
            return badRequestError(res, messages.invalid_file_selected);
        }
        const subCategory = await SubCategory.add({ name, sub_category_code, category_id, is_upcomming });
        if (!subCategory) {
            logger.log(level.info, `createSubCategory Error`)
            return badRequestError(res, messages.invalid_input, null, HTTPStatus.NOT_FOUND);
        }

        const s3Location = `${therapyS3Folder}${subCategory.id}/thumbnail/${fileName}${filePath.ext}`;
        const s3Location2 = `${therapyS3Folder}${subCategory.id}/thumbnail/${fileName2}${filePath2.ext}`;   

         if((therapyS3Folder!==null && subCategory.id !== null && fileName3 !== null && filePath3 !== null) && (therapyS3Folder!==undefined && subCategory.id !== undefined && fileName3 !== undefined && filePath3 !== undefined)){
            s3Location3 = `${therapyS3Folder}${subCategory.id}/thumbnail/${fileName3}${filePath3.ext}`;
         }
            
        await uploadFileToS3(process.env.Aws_Bucket_Name, s3Location, file[0]).then((result, error) => {
            if (!error) {
                SubCategory.update({ _id: subCategory._id }, { thumbnail_url: s3Location });
            } else {
                logger.log(level.error, `createSubCategory Error : Thumbnail upload : ${beautify(error)}`);
            }
        });

        await uploadFileToS3(process.env.Aws_Bucket_Name, s3Location2, zoneimage[0]).then((result, error) => {
            if (!error) {
                SubCategory.update({ _id: subCategory._id }, { thumbnail_url2: s3Location2 });
            } else {
                logger.log(level.error, `createSubCategory Error : Thumbnail2 upload : ${beautify(error)}`);
            }
        });

        if(s3Location3){
            await uploadFileToS3(process.env.Aws_Bucket_Name, s3Location3, affirmationzoneimge[0]).then((result, error) => {
                if (!error) {
                    SubCategory.update({ _id: subCategory._id }, { affirmationzoneimge: s3Location3 });
                } else {
                    logger.log(level.error, `createSubCategory Error : Thumbnail3 upload : ${beautify(error)}`);
                }
            });
            subCategory['affirmationzoneimge'] = await getSignedUrl(process.env.Aws_Bucket_Name, s3Location3);
        }
       subCategory['thumbnail_url'] = await getSignedUrl(process.env.Aws_Bucket_Name, s3Location);
       subCategory['thumbnail_url2'] = await getSignedUrl(process.env.Aws_Bucket_Name, s3Location2);
        logger.log(level.info, `createSubCategory subCategory=${beautify(subCategory)}`);

        return okResponse(res, messages.created.replace("{dynamic}", "Sub Category"), subCategory);

    } catch (error) {
        logger.log(level.error, `createSubCategory Error: ${beautify(error.message)}`);
        return internalServerError(res, error)
    }
}

export const updateSubCategory = async (req, res) => {
    try {
        const { body, params, files } = req;

        if(Object.keys(files).length != 0){  var { file, zoneimage, affirmationzoneimge  } = files}

        const { name, category_id, sub_category_code, is_upcomming } = body;
        const { subCatId } = params;
        logger.log(level.info, `updateSubCategory body=${beautify(body)} \n params=${beautify(params)}`);

        const therapyS3Folder = process.env.Aws_Upload_Path_For_Sub_Categories;
        let filePath, fileName, s3Location,filePath2,fileName2,s3Location2, filePath3,fileName3,s3Location3;
        

        const notExist = await returnOnNotExist(SubCategory, { _id: subCatId, ...deletedCondition }, res, "Sub Category", messages.not_exist.replace("{dynamic}", "Sub Category"));
        if (notExist) return;

        const payload = {};

        if (category_id) {
            const notExist = await returnOnNotExist(Category, { _id: category_id, ...deletedCondition }, res, "Category", messages.not_exist.replace("{dynamic}", "Category"));
            if (notExist) return;
            payload['category_id'] = category_id;
        }


        if (name) {
            const isExist = await returnOnExist(SubCategory, { name, category_id: category_id, _id: { $ne: subCatId }, ...deletedCondition }, res, "Sub Category name is", messages.already_exist.replace('{dynamic}', "Sub Category Name"))
            if (isExist) return;
            payload['name'] = name;
        }

        if (sub_category_code) {
            const isExist = await returnOnExist(SubCategory, { sub_category_code, _id: { $ne: subCatId }, ...deletedCondition }, res, "Sub Category code is", messages.already_exist.replace('{dynamic}', "Sub Category Code"))
            if (isExist) return;
            payload['sub_category_code'] = sub_category_code;
        }

        if (is_upcomming != undefined && is_upcomming != null) payload['is_upcomming'] = is_upcomming;

        const subCategory = await SubCategory.update({ _id: subCatId, ...deletedCondition }, payload);
        if (!subCategory) {
            logger.log(level.info, `updateSubCategory Error`)
            return badRequestError(res, messages.invalid_input);
        }

        if(Object.keys(files).length != 0){
           if(file){
                if (file[0]) {

                    filePath = Path.parse(file[0].originalname);
                    fileName = generateRandomString();   
        
                    if (!(Object.values(IMAGE_EXTENSIONS).includes(filePath.ext))) {
                        logger.log(level.info, 'updateSubCategory invalid file selection error')
                        return badRequestError(res, messages.invalid_file_selected);
                    } 
        
                    s3Location = `${therapyS3Folder}${subCatId}/thumbnail/${fileName}${filePath.ext}`;
                    logger.log(level.info, `\n\ns3Location :::: ${s3Location}`);
        
                    await uploadFileToS3(process.env.Aws_Bucket_Name, s3Location, file[0]).then((result, error) => {
                        if (!error) {
                            SubCategory.update({ _id: subCatId, ...deletedCondition }, { thumbnail_url: s3Location });
                        } else {
                            logger.log(level.error, `updateSubCategory Error : Thumbnail upload : ${beautify(error)}`);
                        }
                    });
                    subCategory['thumbnail_url'] = await getSignedUrl(process.env.Aws_Bucket_Name, s3Location);
                }
            }

           if(zoneimage){
                if(zoneimage[0]){

                    filePath2 = Path.parse(zoneimage[0].originalname);
                    fileName2 = generateRandomString();
        
                    if (!(Object.values(IMAGE_EXTENSIONS).includes(filePath2.ext))) {
                        logger.log(level.info, 'createSubCategory invalid file selection error')
                        return badRequestError(res, messages.invalid_file_selected);
                    }   

                    s3Location2 = `${therapyS3Folder}${subCatId}/thumbnail/${fileName2}${filePath2.ext}`;
                    logger.log(level.info, `\n\ns3Location2 :::: ${s3Location2}`);
    
                    await uploadFileToS3(process.env.Aws_Bucket_Name, s3Location2, zoneimage[0]).then((result, error) => {

                        if (!error) {
                            SubCategory.update({ _id: subCatId, ...deletedCondition }, { thumbnail_url2: s3Location2 });
                        } else {
                            logger.log(level.error, `updateSubCategory Error : Thumbnail2 upload : ${beautify(error)}`);
                        }
                    });
                    subCategory['thumbnail_url2'] = await getSignedUrl(process.env.Aws_Bucket_Name, s3Location2);
                }
            }

           if(affirmationzoneimge){
                if(affirmationzoneimge[0]){
                    
                    filePath3 = Path.parse(affirmationzoneimge[0].originalname);
                    fileName3 = generateRandomString();
        
                    if (!(Object.values(IMAGE_EXTENSIONS).includes(filePath3.ext))) {
                        logger.log(level.info, 'createSubCategory affirmationzoneimge file selection error')
                        return badRequestError(res, messages.invalid_file_selected);
                    }   

                    s3Location3 = `${therapyS3Folder}${subCatId}/thumbnail/${fileName3}${filePath3.ext}`;
                    logger.log(level.info, `\n\ns3Location3 :::: ${s3Location3}`);
    
                    await uploadFileToS3(process.env.Aws_Bucket_Name, s3Location3, affirmationzoneimge[0]).then((result, error) => {

                        if (!error) {
                            SubCategory.update({ _id: subCatId, ...deletedCondition }, { affirmationzoneimge: s3Location3 });
                        } else {
                            logger.log(level.error, `updateSubCategory Error : affirmationzoneimge upload : ${beautify(error)}`);
                        }
                    });
                    subCategory['thumbnail_url3'] = await getSignedUrl(process.env.Aws_Bucket_Name, s3Location3);
                }
            }
        }
        logger.log(level.info, `updateSubCategory sub-category=${beautify(subCategory)}`);
        return okResponse(res, messages.updated.replace("{dynamic}", "Category"), subCategory);

    } catch (error) {
        logger.log(level.error, `updateSubCategory Error: ${beautify(error.message)}`);
        return internalServerError(res, error);
    }
}

export const deleteSubCategory = async (req, res) => {
    try {
        const { params } = req;
        const { subCatId } = params;
        const deletePayload = { is_deleted: true, deleted_at: new Date().toISOString() }

        await SubCategory.update({ _id: subCatId, ...deletedCondition }, deletePayload);
        logger.log(level.info, `sub category deleted ${subCatId}`);

        // Delete Sub category from sub category therapy table which has multiple sub category linked
        const multiLinkFilter = {
            $and: [
                { $expr: { $gt: [{ $size: "$sub_category_id" }, 1] } },
                { sub_category_id: subCatId },
                deletedCondition
            ]
        }
        await SubCategoryTherapy.updateMany(multiLinkFilter, { $pull: { sub_category_id: subCatId } });
        logger.log(level.info, `sub category therapy Multi link Pull`);

        const singleLinkFilter = {
            $and: [
                { $expr: { $lte: [{ $size: "$sub_category_id" }, 1] } },
                { sub_category_id: subCatId },
                deletedCondition
            ]
        }
        const subCategoryTherapy = (await SubCategoryTherapy.get(singleLinkFilter));
        const therapyToBeDeleted = subCategoryTherapy.map(item => item.therapy_id);
        const subCategoryTherapy_records = subCategoryTherapy.map(item => item._id);
        for (let i = 0; i < subCategoryTherapy_records.length; i++) {
            const filter = { _id: subCategoryTherapy_records[i] }
            await SubCategoryTherapy.update(filter, deletePayload);
        }
        logger.log(level.info, `sub category therapy single link`);

        // Delete Therapy
        if (therapyToBeDeleted.length > 0) {
            for (let i = 0; i < therapyToBeDeleted.length; i++) {
                const filter = { _id: therapyToBeDeleted[i], ...deletedCondition }
                await Therapy.update(filter, deletePayload);
            }
        }
        logger.log(level.info, `therapy updated ${beautify(therapyToBeDeleted)}`);

        // Delete Resource
        const multiLinkedResource = {
            $and: [
                { $expr: { $gt: [{ $size: "$therapy_ids" }, 1] } },
                { therapy_ids: { $in: [...therapyToBeDeleted] } },
                deletedCondition
            ]
        }
        const therapyResources_record = await TherapyResources.get(multiLinkedResource);
        const therapyResource_records_ids = therapyResources_record.map(item => item._id);
        for (let i = 0; i < therapyResource_records_ids.length; i++) {
            const filter = { _id: therapyResource_records_ids[i] }
            await TherapyResources.update(filter, { $pull: { therapy_ids: { $in: [...therapyToBeDeleted] } } });
        }
        logger.log(level.info, `therapy resource multi linked`);

        const singleLinkedResource = {
            $and: [
                { $expr: { $lte: [{ $size: "$therapy_ids" }, 1] } },
                { therapy_ids: { $in: [...therapyToBeDeleted] } },
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


        // delete intro video & resource
        const introFilter = { content_type: INTRO_VIDEO_FOR.SUBCATEGORY, sub_category_id: subCatId }
        const intro = await IntroVideos.get(introFilter);
        const introResourceIds = intro.map(item => item.resource_id);
        const intro_records = intro.map(item => item._id);
        for (let i = 0; i < intro_records.length; i++) {
            await IntroVideos.update({ _id: intro_records[i] }, deletePayload)
        }
        logger.log(level.info, `intro video delete: ${beautify(introResourceIds)}`);
        if (introResourceIds.length > 0) {
            for (let i = 0; i < introResourceIds.length; i++) {
                await Resource.update({ _id: introResourceIds[i] }, deletePayload);
            }
            logger.log(level.info, `intro video resource delete`);
        }

        // Delete Medicinal Music
        const multiLinkFilterForMedicinalMusic = {
            $and: [
                { $expr: { $gt: [{ $size: "$sub_category_id" }, 1] } },
                { sub_category_id: subCatId },
                deletedCondition
            ]
        }
        const subCategoryResource = await SubCategoryResource.get(multiLinkFilterForMedicinalMusic);
        for (let i = 0; i < subCategoryResource.length; i++) {
            await SubCategoryResource.update({ _id: subCategoryResource[i]._id }, { $pull: { sub_category_id: subCatId } });
        }
        logger.log(level.info, `sub category resource multi link pull`);

        const singleLinkFilterForMedicinalMusic = {
            $and: [
                { $expr: { $lte: [{ $size: "$sub_category_id" }, 1] } },
                { sub_category_id: subCatId },
                deletedCondition
            ]
        }
        const resourceToBeDeleted_records = await SubCategoryResource.get(singleLinkFilterForMedicinalMusic);
        const resourceToBeDeleted = resourceToBeDeleted_records.map(item => item.resource_id);
        const resourceToBeDeleted_id = resourceToBeDeleted_records.map(item => item._id);
        for (let i = 0; i < resourceToBeDeleted_id.length; i++) {
            await SubCategoryResource.update({ _id: resourceToBeDeleted_id[i] }, deletePayload);
        }
        logger.log(level.info, `sub category resource single link delete`);
        for (let i = 0; i < resourceToBeDeleted.length; i++) {
            await Resource.update({ _id: resourceToBeDeleted[i], ...deletedCondition }, deletePayload);
        }
        logger.log(level.info, `sub category resource delete ${beautify(resourceToBeDeleted)}`);

        return okResponse(res, messages.deleted.replace("{dynamic}", "Sub Category"));

    } catch (error) {
        logger.log(level.error, `deleteSubCategory Error: ${beautify(error.message)}`);
        return internalServerError(res, error);
    }
}