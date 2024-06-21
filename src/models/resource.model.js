import mongoose from "mongoose";
import { RESOURCE_FORMAT } from "../shared/constant/types.const.js";
import DBOperation from "../shared/services/database/database_operation.service.js";
import SchemaMethods from "../shared/services/database/schema_methods.service.js";
import { signURL } from "../shared/services/file-upload/aws-s3.service.js";

// mongoose schema
const schema = {
  name: {
    type: String,
    required: true,
    default: ""
  },
  url: {
    type: String,
    required: false,
    default: "",
  },
  resource_type_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "ResourceType",
    required: false,
    default: ""
  },
  format: {
    type: Number,   /* 1 : video, 2: audio */
    required: true,
    default: 1,
    enum: [RESOURCE_FORMAT.VIDEO, RESOURCE_FORMAT.AUDIO]
  },
  thumbnail_url: {
    type: String,
    required: false,
    trim: true,
    default: ""
  },
  description: {
    type: String,
    required: true,
    default: "",
  },
  status: {
    type: Number,
    required: true,
    default: 1,
  },
  /* duration: {
    type: String,
    required: true,
  }, */
  is_upcomming: {
    type: Boolean,
    required: false,
    default: false
  },
  is_deleted: {
    type: Boolean,
    default: false
  },
  deleted_at: {
    type: Date,
    default: ""
  },
  how_works_title: {

    type: String,
    default: ""
  },
  how_works_description: {
    type: String,
    default: ""

  }

};
const modelName = "Resource";
const ResourceSchema = DBOperation.createSchema(modelName, schema);

ResourceSchema.post(["find", 'update', 'updateMany'], handleURL);
ResourceSchema.post("aggregate", handleURL);
ResourceSchema.post(["findOne", "findOneAndUpdate", "updateOne"], handleSingleURL);
ResourceSchema.post("save", handleSingleURL);

async function handleURL(values) {
  values.map(async (item) => {
    item.thumbnail_url = await signURL(item.thumbnail_url)
    item.url = await signURL(item.url)
  });
  return values;
}

async function handleSingleURL(value) {
  if (!value) return;
  value.thumbnail_url = await signURL(value.thumbnail_url);
  value.url = await signURL(value.url);
  return value;
}



ResourceSchema.virtual("resource_type", {
  ref: 'ResourceType',
  localField: 'resource_type_id',
  foreignField: '_id',
  justOne: true
})

let ResourceModel = DBOperation.createModel(modelName, ResourceSchema);
const Resource = new SchemaMethods(ResourceModel);
export default Resource;
