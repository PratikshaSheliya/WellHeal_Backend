import mongoose from "mongoose";
import { INTRO_VIDEO_FOR } from "../shared/constant/types.const.js";
import DBOperation from "./../shared/services/database/database_operation.service.js";
import SchemaMethods from "./../shared/services/database/schema_methods.service.js";

// mongoose schema
const schema = {
  name: {
    type: String,
    required: true,
    trim: true,
    default: "",
  },
  description: {
    type: String,
    required: false,
    trim: true,
    default: "",
  },
  category_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Category",
    required: false,
    trim: true,
  },
  sub_category_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "SubCategory",
    required: false,
    trim: true,
  },
  resource_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Resource",
    required: true,
    trim: true,
  },
  content_type: {
    type: Number,
    required: true,
    trim: true,
    default: INTRO_VIDEO_FOR.SUBCATEGORY,
    enum: Object.values(INTRO_VIDEO_FOR)
  },
  is_deleted: {
    type: Boolean,
    default: false
  },
  deleted_at: {
    type: Date,
    default: null
  }
};
const modelName = "IntroVideos";
const IntroVideosSchema = DBOperation.createSchema(modelName, schema);
IntroVideosSchema.virtual("category", {
  ref: 'Category',
  localField: 'category_id',
  foreignField: '_id',
  justOne: true
})
IntroVideosSchema.virtual("sub_category", {
  ref: 'SubCategory',
  localField: 'sub_category_id',
  foreignField: '_id',
  justOne: true
})
IntroVideosSchema.virtual("resource", {
  ref: 'Resource',
  localField: 'resource_id',
  foreignField: '_id',
  justOne: true
})
let IntroVideosModel = DBOperation.createModel(modelName, IntroVideosSchema);
const IntroVideos = new SchemaMethods(IntroVideosModel);
export default IntroVideos;
