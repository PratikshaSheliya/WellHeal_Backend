import logger, { level } from "../config/logger.js";
import { beautify, internalServerError, okResponse, toObjectId, parseSearchOptions } from "../shared/utils/utility.js";
import IntroVideos from "../models/intro_videos.model.js";
import messages from "../shared/constant/messages.const.js";

export const getIntroVideoList = async (req, res) => {
  try {
    const { query } = req;
    const { option = {}, category_id, sub_category_id, content_type } = query;
    const { sort = { created_at: -1 } } = option;
    option['sort'] = sort;

    const searchFilter = await parseSearchOptions(option);
    const filter = { is_deleted: false, ...searchFilter };

    if (content_type) filter['content_type'] = content_type
    if (category_id) filter['category_id'] = toObjectId(category_id);
    if (sub_category_id) filter['sub_category_id'] = toObjectId(sub_category_id);

    logger.log(level.info, `getIntroVideoList query=${beautify(query)}`)

    const response = await IntroVideos.get(filter, null, option, { path: 'resource' });
    // const total = await IntroVideos.count(filter);
    const total = await response.length;
    return okResponse(res, messages.record_fetched, response, total);

  } catch (error) {
    logger.log(level.error, `getIntroVideoList Error: ${beautify(error.message)}`);
    return internalServerError(res, error)
  }
}