import logger, { level } from "../../config/logger.js";
import { MODAL_ID } from "../constant/types.const.js";
import { beautify, getPaginationOptions, insertIf } from "../utils/utility.js";

export const getAverageRatingByTherapyPipeline = (filter, option = null) => {
    logger.log(level.info, `Pipeline getAverageByTherapyPipeline args=${beautify(filter)} option=${beautify(option)}`);
    const opArgs = getPaginationOptions(option);
    logger.log(level.debug, `opArgs=${beautify(opArgs)}`);
    const pipeline = [
        { $match: { ...filter } },
        {
            $lookup: {
                'from': 'reviewratings',
                'localField': '_id',
                'foreignField': 'therapy_id',
                'as': 'ratings'
            }
        },
        {
            $set: {
                'average_rating': { $avg: "$ratings.rating" },
            }
        },
        { '$unset': ['__v', 'id', '_id', 'ratings'] },
        ...opArgs,
    ];
    logger.log(level.info, `Pipeline getAverageByTherapyPipeline ${beautify(pipeline)}`);
    return pipeline;
}
    ;
export const getTherapyWithProgress = (filter, option = null, isCompleted = false) => {
    logger.log(level.info, `Pipeline getTherapyWithProgress args=${beautify(filter)} option=${beautify(option)} isCompleted=${isCompleted}`);
    const opArgs = getPaginationOptions(option);
    logger.log(level.debug, `opArgs=${beautify(opArgs)}`);
    const pipeline = [
        { $match: { ...filter } },
        {
            $lookup: {
                from: 'therapyresources',
                localField: 'resource_id',
                foreignField: 'resource_id',
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
            $match: {
                'resource.is_deleted': false
            }
        },
        {
            $group: {
                '_id': {
                    'sub_category_id': '$sub_category_id',
                    'therapy_id': '$therapy_id'
                },
                'total_progress': {
                    $sum: '$progress_percent'
                }
            }
        },
        {
            $lookup: {
                from: 'therapyresources',
                let: { 'tid': '$_id.therapy_id' },
                pipeline: [
                    { $match: { $expr: { $in: ['$$tid', '$therapy_ids'] } } },
                    { $match: { $expr: { $eq: ['$is_deleted', false] } } }
                ],
                as: 'resource'
            }
        },
        {
            $lookup: {
                from: 'resources',
                let: { rid: '$resource.resource_id' },
                pipeline: [
                    { $match: { $expr: { $in: ['$_id', '$$rid'] } } },
                    { $match: { $expr: { $eq: ['$is_deleted', false] } } },
                    {
                        $match: {
                            $or: [
                                { $expr: { $eq: ['$is_upcomming', false] } },
                                { $expr: { $eq: [{ $type: "$is_upcomming" }, "missing"] } }
                            ]
                        }
                    }
                ],
                as: 'resource'
            }
        },
        {
            $set: {
                total_resources: { '$size': '$resource' },
                completed: { $cond: [{ $size: '$resource' }, { '$divide': ['$total_progress', { $size: '$resource' }] }, 0] }
            }
        },
        {
            $lookup: {
                from: 'therapies',
                let: { 'tid': '$_id.therapy_id' },
                pipeline: [
                    { $match: { $expr: { $eq: ['$$tid', '$_id'] } } },
                    { $match: { $expr: { $eq: ['$is_deleted', false] } } }
                ],
                as: 'therapy'
            }
        },
        {
            $unwind: {
                path: '$therapy',
                preserveNullAndEmptyArrays: false
            }
        },
        {
            $lookup: {
                from: 'subcategories',
                let: { 'sbid': '$_id.sub_category_id' },
                pipeline: [
                    { $match: { $expr: { $eq: ['$$sbid', '$_id'] } } },
                    { $match: { $expr: { $eq: ['$is_deleted', false] } } }
                ],
                as: 'sub_category'
            }
        },
        {
            $unwind: {
                path: '$sub_category',
                preserveNullAndEmptyArrays: false
            }
        },
        {
            $set: {
                'therapy.therapy_id': '$therapy._id',
                'therapy.completed': '$completed',
                'therapy.sub_category': '$sub_category'
            }
        },
        { $replaceRoot: { 'newRoot': '$therapy' } },
        {
            $set: {
                'sub_category.sub_category_id': '$sub_category._id'
            }
        },
        { '$unset': ['_id', '__v', 'sub_category._id', 'sub_category.__v'] },
        ...insertIf((isCompleted == true || isCompleted == 'true'), { $match: { $expr: { $eq: ['$completed', 100] } } }, { $match: { $expr: { $lt: ['$completed', 100] } } })
    ];

    const countPipeline = [...pipeline];
    pipeline.push(...opArgs);
    logger.log(level.info, `Pipeline getTherapyWithProgress ${beautify(pipeline)}`);
    return { pipeline, countPipeline };
};

export const getProgressOfTherapies = async (filter) => {
    logger.log(level.info, `Pipeline getProgressOfTherapies args=${beautify(filter)}`);
    const pipeline = [
        { $match: { ...filter } },
        {
            $group: {
                _id: { 'sub_category_id': '$sub_category_id', 'therapy_id': '$therapy_id' },
                viewed_resource: { $count: {} },
                total_progress: { $sum: '$progress_percent' }
            }
        },
        {
            $lookup: {
                from: 'therapyresources',
                let: { tid: '$_id.therapy_id' },
                pipeline: [
                    { $match: { $expr: { $in: ['$$tid', '$therapy_ids'] } } },
                    { $match: { $expr: { $eq: ['$is_deleted', false] } } }
                ],
                as: 'resource'
            }
        },
        {
            $lookup: {
                from: 'resources',
                let: { rid: '$resource.resource_id' },
                pipeline: [
                    { $match: { $expr: { $in: ['$_id', '$$rid'] } } },
                    { $match: { $expr: { $eq: ['$is_deleted', false] } } },
                    {
                        $match: {
                            $or: [
                                { $expr: { $eq: ['$is_upcomming', false] } },
                                { $expr: { $eq: [{ $type: "$is_upcomming" }, "missing"] } }
                            ]
                        }
                    }
                ],
                as: 'resource'
            }
        },
        {
            $set: {
                completed: { $cond: [{ $size: '$resource' }, { '$divide': ['$total_progress', { $size: '$resource' }] }, 0] },
                therapy_id: '$_id.therapy_id'
            }
        },
        { $unset: ['_id', 'viewed_resource', 'total_progress', 'resource'] }
    ]
    logger.log(level.info, `Pipeline getProgressOfTherapies ${beautify(pipeline)}`);
    return pipeline;
}

export const getRecentTherapyPipeline =async (option) => {
    option['limit'] = null;
    option['offset'] = null;
    logger.log(level.info, `Pipeline getRecentTherapyPipeline option=${beautify(option)}`);
    const opArgs = getPaginationOptions(option);
    logger.log(level.debug, `opArgs=${beautify(opArgs)}`);
    const pipeline = [
        {
            $match: {
                $expr: { $gte: [{ '$size': '$sub_category_id' }, 1] },
                'is_deleted': false
            }
        },
        {
            $lookup: {
                from: 'therapies',
                let: { 'tid': '$therapy_id' },
                pipeline: [
                    { $match: { $expr: { $eq: ['$_id', '$$tid'] } } },
                    { $match: { $expr: { $eq: ['$is_deleted', false] } } },
                    {
                        $match: {
                            $or: [
                                { $expr: { $eq: ['$is_upcomming', false] } },
                                { $expr: { $eq: [{ $type: '$is_upcomming' }, 'missing'] } }
                            ]
                        }
                    }
                ],
                'as': 'therapy'
            }
        },
        {
            $unwind: {
                'path': '$therapy',
                'preserveNullAndEmptyArrays': false
            }
        },
        // { $replaceRoot: { 'newRoot': '$therapy' } },
        // {
        //     $set: {
        //         [MODAL_ID.Therapy]: '$_id'
        //     }
        // },
        { $unset: ['_id', '__v'] }
    ]

    const countPipeline = [...pipeline];
    pipeline.push(...opArgs);
    logger.log(level.info, `Pipeline getRecentTherapyPipeline ${beautify(pipeline)}`);
    return { pipeline, countPipeline };

}