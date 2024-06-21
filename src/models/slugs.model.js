import mongoose from "mongoose";
import { SLUG_TYPE, SLUG_RESOURCE_FORMAT  } from "../shared/constant/types.const.js";
import DBOperation from "../shared/services/database/database_operation.service.js";
import SchemaMethods from "../shared/services/database/schema_methods.service.js";
import { signURL } from "../shared/services/file-upload/aws-s3.service.js";


// mongoose schema
const schema = {
  content_type: {
    type: Number,
    required: true,
    trim: true,
    default: "",
    enum: Object.values(SLUG_TYPE)
  },
  title: {
    type: String,
    required: false,
    trim: true,
    default: "",
  },
  description: {
    type: String,
    required: false,
    trim: true,
    default: "",
  },
  url: {
    type: String,
    required: false,
    trim: true,
    default: "",
  },
  format: {
    type: Number,   /* 1: Image , 2: video */
    required: true,
    default: 1,
    enum: [SLUG_RESOURCE_FORMAT.IMAGE, SLUG_RESOURCE_FORMAT.VIDEO]
  },
  user_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: false,
    trim: true,
  },
  ios_version: {
    type: String,
    required: false,
    trim: true,
    default: "",
  }
};
const modelName = "Slug";
const SlugSchema = DBOperation.createSchema(modelName, schema);
SlugSchema.post(["find", 'update', 'updateMany'], handleURL);
SlugSchema.post("aggregate", handleURL);
SlugSchema.post(["findOne", "findOneAndUpdate", "updateOne"], handleSingleURL);
SlugSchema.post("save", handleSingleURL);

async function handleURL(values) {
  values.map(async (item) => item.url = await signURL(item.url));
  return values;
}

async function handleSingleURL(value) {
  if (!value) return;
  value.url = await signURL(value.url);
  return value;
}

let SlugModel = DBOperation.createModel(modelName, SlugSchema);
const Slug = new SchemaMethods(SlugModel);
export default Slug;
