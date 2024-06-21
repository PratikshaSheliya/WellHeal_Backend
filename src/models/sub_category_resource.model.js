import mongoose from "mongoose";
import DBOperation from "../shared/services/database/database_operation.service.js";
import SchemaMethods from "../shared/services/database/schema_methods.service.js";
import { signURL } from "../shared/services/file-upload/aws-s3.service.js";

// mongoose schema
const schema = {
  resource_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Resource",
    required: true,
    trim: true,
  },
  sub_category_id: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: "SubCategory"
  }],
  is_deleted: {
    type: Boolean,
    default: false
  },
  deleted_at: {
    type: Date,
    default: null
  }
};
const modelName = "SubCategoryResource";
const SubCatResourceSchema = DBOperation.createSchema(modelName, schema);

SubCatResourceSchema.post(["find", 'update', 'updateMany'], handleURL);
SubCatResourceSchema.post("aggregate", handleURL);
SubCatResourceSchema.post(["findOne", "findOneAndUpdate", "updateOne"], handleSingleURL);
SubCatResourceSchema.post("save", handleSingleURL);

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

SubCatResourceSchema.virtual("resource", {
  ref: 'Resource',
  localField: 'resource_id',
  foreignField: '_id',
  justOne: true
})

SubCatResourceSchema.virtual("sub_category", {
  ref: 'SubCategory',
  localField: 'sub_category_id',
  foreignField: '_id'
})

let ResourceModel = DBOperation.createModel(modelName, SubCatResourceSchema);
const SubCategoryResource = new SchemaMethods(ResourceModel);
export default SubCategoryResource;
