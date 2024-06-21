import mongoose from "mongoose";
import { signURL } from "../shared/services/file-upload/aws-s3.service.js";
import DBOperation from "./../shared/services/database/database_operation.service.js";
import SchemaMethods from "./../shared/services/database/schema_methods.service.js";

// mongoose schema
const schema = {
  resource_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Resource",
    required: true,
    trim: true,
  },
  therapy_ids: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: "Therapy"
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
const modelName = "TherapyResources";
const TherapyResourcesSchema = DBOperation.createSchema(modelName, schema);
TherapyResourcesSchema.virtual("resource", {
  ref: 'Resource',
  localField: 'resource_id',
  foreignField: '_id',
  justOne: true
})
TherapyResourcesSchema.virtual("therapy", {
  ref: 'Therapy',
  localField: 'therapy_ids',
  foreignField: '_id',
})


TherapyResourcesSchema.post(["find", 'update', 'updateMany'], handleURL);
TherapyResourcesSchema.post("aggregate", handleURL);
TherapyResourcesSchema.post(["findOne", "findOneAndUpdate", "updateOne"], handleSingleURL);
TherapyResourcesSchema.post("save", handleSingleURL);

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


let TherapyResourcesModel = DBOperation.createModel(modelName, TherapyResourcesSchema);
const TherapyResources = new SchemaMethods(TherapyResourcesModel);
export default TherapyResources;
