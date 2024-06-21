import logger, { level } from "../../config/logger.js";
import { FAVORITE_CONTENT_TYPE, MODAL_ID } from "../constant/types.const.js";
import { beautify, getPaginationOptions, insertIf, toObjectId } from "../utils/utility.js";

export const getResourceByTherapyIdPipeline = async(filter, userid, option = null, optionalFilter = null, searchFilter ) => {
    logger.log(level.info, `Pipeline getResourceByTherapyId args=${beautify(filter)} option=${beautify(option)} userId=>${userid}`);
    const opArgs = getPaginationOptions(option);
    logger.log(level.debug, `opArgs=${beautify(opArgs)}`);
    const pipeline = [
        { $match: { ...filter } },
        {
            $lookup: {
                'from': 'resources',
                'localField': 'resource_id',
                'foreignField': '_id',
                'as': 'resource'
            }
        },
        { $unwind: { 'path': '$resource', "preserveNullAndEmptyArrays": true } },
        ...insertIf(optionalFilter && optionalFilter.format, { $match: { 'resource.format': optionalFilter.format } }),
        {
            $lookup: {
                'from': 'therapies',
                'let': { 'tids': '$therapy_ids' },
                'pipeline': [
                    { $match: { $expr: { $in: ['$_id', '$$tids'] } } },
                    { $set: { [MODAL_ID.Therapy]: '$_id' } },
                    { $unset: ['__v', '_id', 'id'] }
                ],
                'as': 'therapy'
            }
        },
        {
            $lookup: {
                from: 'subcategorytherapies',
                localField: 'therapy_ids',
                foreignField: 'therapy_id',
                as: 'sub_category_therapy'
            }
        },
        {
            $lookup: {
                from: 'subcategories',
                localField: 'sub_category_therapy.sub_category_id',
                foreignField: '_id',
                as: 'sub_category'
            }
        },
        {
            $lookup: {
                from: 'categories',
                localField: 'sub_category.category_id',
                foreignField: '_id',
                as: 'category'
            }
        },
        {
            $addFields: {
                'sub_category': {
                    $map: {
                        input: "$sub_category",
                        as: "item",
                        in: { $mergeObjects: ['$$item', { [MODAL_ID.SubCategory]: "$$item._id" }] }
                    }
                },
                'category': {
                    $map: {
                        input: "$category",
                        as: "item",
                        in: { $mergeObjects: ['$$item', { [MODAL_ID.Category]: "$$item._id" }] }
                    }
                }
            }
        },
        {
            $set: {
                "resource.therapy": '$therapy',
                "resource.sub_category": '$sub_category',
                "resource.category": '$category'
            }
        },
        { $unset: ['resource.sub_category._id', 'resource.sub_category.__v', 'resource.category._id', 'resource.category.__v'] },
        { $match: { ...searchFilter } },
        { $replaceRoot: { 'newRoot': '$resource' } },
        {
            $lookup: {
                'from': 'resourcetypes',
                'localField': 'resource_type_id',
                'foreignField': '_id',
                'as': 'resource_type'
            }
        },
        { $unwind: { 'path': '$resource_type', "preserveNullAndEmptyArrays": true } },
        {
            $set: {
                [MODAL_ID.Resource]: "$_id",
                'resource_type': '$resource_type.type',
                'sort_index': { $ifNull: ['$resource_type.sort_index', 0] },
                'is_upcomming': {
                    $ifNull: ["$is_upcomming", false]
                }
            }
        },
        {
            $lookup: {
                from: 'userprogresses',
                let: { 'rid': '$_id' },
                pipeline: [
                    { $match: { $expr: { $eq: ['$$rid', '$resource_id'] } } },
                    { $match: { 'user_id': toObjectId(userid) } }
                ],
                as: 'progress'
            }
        },
        {
            $lookup: {
                from: 'favorites',
                let: { 'frid': '$_id' },
                pipeline: [
                    { $match: { $expr: { $eq: ['$$frid', '$favourite_id'] } } },
                    { $match: { 'user_id': toObjectId(userid) } },
                    { $match: { $expr: { $eq: ['$content_type', `${FAVORITE_CONTENT_TYPE.RESOURCE}`] } } }
                ],
                as: 'favourite'
            }
        },
        {
            '$set': {
                'is_favourite': {
                    $cond: [{ $ne: [{ $size: '$favourite' }, 0] }, true, false]
                },
                'progress_size': { $size: '$progress' },
                'max_progress_doc': {
                    $arrayElemAt: [
                        '$progress',
                        { $indexOfArray: ['$progress.progress_percent', { $max: '$progress.progress_percent' }] }
                    ]
                }
            }
        }, {
            '$set': {
                'progress_percent': {
                    $cond: [{ $eq: ['$progress_size', 0] }, 0, '$max_progress_doc.progress_percent']
                },
                'spent_time': {
                    $cond: [{ $eq: ['$progress_size', 0] }, '00:00:00', '$max_progress_doc.spent_time']
                }
            }
        },
        { '$unset': ['__v', 'id', '_id', 'progress', 'max_progress_doc', 'progress_size', 'favourite'] }
    ];
    const countPipeline = [...pipeline];
    pipeline.push(...opArgs);
    logger.log(level.info, `Pipeline getResourceByTherapyId ${beautify(pipeline)}`);
    return { pipeline, countPipeline };
};

export const getResourceForSubCategoryPipeline = async(filter, userid, option = null, resourceTypeId = null,searchFilter) => {
    logger.log(level.info, `Pipeline getResourceForSubCategory args=${beautify(filter)} option=${beautify(option)}`);
    const opArgs = getPaginationOptions(option);
    logger.log(level.debug, `opArgs=${beautify(opArgs)}`);
    const pipeline = [
        { $match: { ...filter } },
        {
            $lookup: {
                'from': 'resources',
                'localField': 'resource_id',
                'foreignField': '_id',
                'as': 'resource'
            }
        },
        { $unwind: { 'path': '$resource', "preserveNullAndEmptyArrays": true } },
        {
            $lookup: {
                from: 'subcategories',
                localField: 'sub_category_id',
                foreignField: '_id',
                as: 'sub_category'
            }
        },
        {
            $addFields: {
                'sub_category': {
                    $map: {
                        input: "$sub_category",
                        as: "item",
                        in: { $mergeObjects: ['$$item', { [MODAL_ID.SubCategory]: "$$item._id" }] }
                    }
                }
            }
        },
        {
            $match: { 
             ...searchFilter 
            }      
        },
        { $set: { 'resource.sub_category': '$sub_category' } },
        { $replaceRoot: { 'newRoot': '$resource' } },
        {
            $lookup: {
                'from': 'resourcetypes',
                'localField': 'resource_type_id',
                'foreignField': '_id',
                'as': 'resource_type'
            }
        },
        {
            $lookup: {
                from: 'favorites',
                let: { 'frid': '$_id' },
                pipeline: [
                    { $match: { $expr: { $eq: ['$$frid', '$favourite_id'] } } },
                    { $match: { 'user_id': toObjectId(userid) } },
                    { $match: { $expr: { $eq: ['$content_type', `${FAVORITE_CONTENT_TYPE.RESOURCE}`] } } }
                ],
                as: 'favourite'
            }
        },
        {
            $set: {
                'is_favourite': {
                    $cond: [{ $ne: [{ $size: '$favourite' }, 0] }, true, false]
                }
            }
        },
        { $unwind: { 'path': '$resource_type', "preserveNullAndEmptyArrays": true } },
        ...insertIf(resourceTypeId, { $match: { 'resource_type._id': { $eq: toObjectId(resourceTypeId) } } }),
        {
            $set: {
                'resource_id': "$_id",
                'resource_type': '$resource_type.type',
                'sort_index': { $ifNull: ['$resource_type.sort_index', 0] },
            }
        },
        { '$unset': ['__v', 'id', '_id', 'favourite'] }
    ];

    const countPipeline = [...pipeline];

    pipeline.push(...opArgs);

    logger.log(level.info, `Pipeline getResourceByTherapyId ${beautify(pipeline)}`);
    return { pipeline, countPipeline };
}

export const getResourceForAffirmationPipeline = async(filter, userid, option = null, resourceTypeId = null,searchFilter) => {
    logger.log(level.info, `Pipeline getResourceForAffirmationPipeline args=${beautify(filter)} option=${beautify(option)}`);
    const opArgs = getPaginationOptions(option);
    logger.log(level.debug, `opArgs=${beautify(opArgs)}`);
    const pipeline = [
        { $match: { ...filter } },
        {
            $lookup: {
                'from': 'resources',
                'localField': 'resource_id',
                'foreignField': '_id',
                'as': 'resource'
            }
        },
        { $unwind: { 'path': '$resource', "preserveNullAndEmptyArrays": true } },
        {
            $lookup: {
                from: 'subcategories',
                localField: 'sub_category_id',
                foreignField: '_id',
                as: 'sub_category'
            }
        },
        {
            $addFields: {
                'sub_category': {
                    $map: {
                        input: "$sub_category",
                        as: "item",
                        in: { $mergeObjects: ['$$item', { [MODAL_ID.SubCategory]: "$$item._id" }] }
                    }
                }
            }
        },
        {
            $match: { 
             ...searchFilter 
            }      
        },
        { $set: { 'resource.sub_category': '$sub_category' } },
        { $replaceRoot: { 'newRoot': '$resource' } },
        {
            $lookup: {
                'from': 'resourcetypes',
                'localField': 'resource_type_id',
                'foreignField': '_id',
                'as': 'resource_type'
            }
        },
        {
            $lookup: {
                from: 'favorites',
                let: { 'frid': '$_id' },
                pipeline: [
                    { $match: { $expr: { $eq: ['$$frid', '$favourite_id'] } } },
                    { $match: { 'user_id': toObjectId(userid) } },
                    { $match: { $expr: { $eq: ['$content_type', `${FAVORITE_CONTENT_TYPE.RESOURCE}`] } } }
                ],
                as: 'favourite'
            }
        },
        {
            $set: {
                'is_favourite': {
                    $cond: [{ $ne: [{ $size: '$favourite' }, 0] }, true, false]
                }
            }
        },
        { $unwind: { 'path': '$resource_type', "preserveNullAndEmptyArrays": true } },
        ...insertIf(resourceTypeId, { $match: { 'resource_type._id': { $eq: toObjectId(resourceTypeId) } } }),
        {
            $set: {
                'resource_id': "$_id",
                'resource_type': '$resource_type.type',
                'sort_index': { $ifNull: ['$resource_type.sort_index', 0] },
            }
        },
        { '$unset': ['__v', 'id', '_id', 'favourite'] }
    ];

    const countPipeline = [...pipeline];

    pipeline.push(...opArgs);

    logger.log(level.info, `Pipeline getResourceByTherapyId ${beautify(pipeline)}`);
    return { pipeline, countPipeline };
}
export const getAffirmationSubcategoryListPipeline = async(filter, userid, option = null, resourceTypeId = null) => {
    logger.log(level.info, `Pipeline getAffirmationSubcategoryListPipeline args=${beautify(filter)} option=${beautify(option)}`);
    const opArgs = getPaginationOptions(option);
    logger.log(level.debug, `opArgs=${beautify(opArgs)}`);
     const pipeline = [
        { $match: { ...filter } },
        {
            $lookup: {
                'from': 'resources',
                'localField': 'resource_id',
                'foreignField': '_id',
                'as': 'resource'
            }
        },
        { $unwind: { 'path': '$resource', "preserveNullAndEmptyArrays": true } },
        {
            $lookup: {
                from: 'subcategories',
                localField: 'sub_category_id',
                foreignField: '_id',
                as: 'sub_category'
            }
        },
        {
            $addFields: {
                'sub_category': {
                    $map: {
                        input: "$sub_category",
                        as: "item",
                        in: { $mergeObjects: ['$$item', { [MODAL_ID.SubCategory]: "$$item._id" }] }
                    }
                }
            }
        },
        { $set: { 'resource.sub_category': '$sub_category' } },
        { $replaceRoot: { 'newRoot': '$resource' } },
        {
            $lookup: {
                'from': 'resourcetypes',
                'localField': 'resource_type_id',
                'foreignField': '_id',
                'as': 'resource_type'
            }
        },
        {
            $lookup: {
                from: 'favorites',
                let: { 'frid': '$_id' },
                pipeline: [
                    { $match: { $expr: { $eq: ['$$frid', '$favourite_id'] } } },
                    { $match: { 'user_id': toObjectId(userid) } },
                    { $match: { $expr: { $eq: ['$content_type', `${FAVORITE_CONTENT_TYPE.RESOURCE}`] } } }
                ],
                as: 'favourite'
            }
        },
        {
            $set: {
                'is_favourite': {
                    $cond: [{ $ne: [{ $size: '$favourite' }, 0] }, true, false]
                }
            }
        },
        { $unwind: { 'path': '$resource_type', "preserveNullAndEmptyArrays": true } },
        ...insertIf(resourceTypeId, { $match: { 'resource_type._id': { $eq: toObjectId(resourceTypeId) } } }),
        {
            $set: {
                'resource_id': "$_id",
                'resource_type': '$resource_type.type',
                'sort_index': { $ifNull: ['$resource_type.sort_index', 0] },
            }
        },
        { '$unset': ['__v', 'id', '_id', 'favourite'] }
    ]; 
    const countPipeline = [...pipeline];

    pipeline.push(...opArgs);

    logger.log(level.info, `Pipeline getAffirmationSubcategoryListPipeline ${beautify(pipeline)}`);
    return { pipeline, countPipeline };
}

export const getTop10MostUsedResource = async (option = null) => {
    logger.log(level.info, `Pipeline getResourceForSubCategory option=${beautify(option)}`);
    const opArgs = getPaginationOptions(option);
    logger.log(level.debug, `opArgs=${beautify(opArgs)}`);
    const pipeline = [
        {
            $group: {
                '_id': '$resource_id',
                'total_view': { $sum: 1 },
                'therapy_ids': { $addToSet: '$therapy_id' },
                'sub_category_ids': { $addToSet: '$sub_category_id' }
            }
        },
        {
            $lookup: {
                from: 'resources',
                let: { 'rid': '$_id' },
                pipeline: [
                    { $match: { $expr: { $eq: ['$_id', '$$rid'] } } },
                    { $match: { 'is_deleted': false } }
                ],
                as: 'resource'
            }
        },
        {
            $unwind: {
                path: '$resource',
                preserveNullAndEmptyArrays: false
            }
        },
        {
            $lookup: {
                from: 'therapies',
                let: { tid: '$therapy_ids' },
                pipeline: [
                    { $match: { $expr: { $in: ['$_id', '$$tid'] } } },
                    { $match: { 'is_deleted': false } },
                    { $set: { [MODAL_ID.Therapy]: '$_id' } },
                    { $unset: ['_id', '__v'] }
                ],
                as: 'therapies'
            }
        },
        {
            $lookup: {
                from: 'subcategories',
                let: {
                    'sid': '$sub_category_ids'
                },
                pipeline: [
                    { $match: { $expr: { $in: ['$_id', '$$sid'] } } },
                    { $match: { 'is_deleted': false } },
                    { $set: { [MODAL_ID.SubCategory]: '$_id' } },
                    { $unset: ['_id', '__v'] }
                ],
                'as': 'subcategories'
            }
        },
        {
            $lookup: {
                from: 'categories',
                let: { 'cid': '$subcategories.category_id' },
                pipeline: [
                    { $match: { $expr: { $in: ['$_id', '$$cid'] } } },
                    { $match: { 'is_deleted': false } },
                    { $set: { [MODAL_ID.Category]: '$_id' } },
                    { $unset: ['_id', '__v'] }
                ],
                as: 'categories'
            }
        },
        {
            $set: {
                [`resource.${MODAL_ID.Resource}`]: '$resource._id',
                'resource.total_use': '$total_view',
                'resource.therapies': '$therapies',
                'resource.subcategories': '$subcategories',
                'resource.categories': '$categories'
            }
        },
        { $replaceRoot: { 'newRoot': '$resource' } },
        { $unset: ['_id', '__v'] },
        ...opArgs
    ];

    logger.log(level.info, `Pipeline getTop10MostUsedResource ${beautify(pipeline)}`);
    return { pipeline };
}