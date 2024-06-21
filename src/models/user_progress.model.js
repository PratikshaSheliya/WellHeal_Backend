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
  therapy_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Therapy",
    required: true,
    trim: true,
  },
  sub_category_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "SubCategory",
    required: true,
    trim: true,
  },
  progress_percent: {
    type: Number,
    trim: true,
    default: 0
  },
  user_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
    trim: true,
  },
  spent_time: {
    type: String,
    required: true,
    trim: true,
    default: "00:00:00"
  }
};
const modelName = "UserProgress";
const UserProgressSchema = DBOperation.createSchema(modelName, schema);
UserProgressSchema.virtual("resource", {
  ref: 'Resource',
  localField: 'resource_id',
  foreignField: '_id',
})
UserProgressSchema.virtual("therapy", {
  ref: 'Therapy',
  localField: 'therapy_id',
  foreignField: '_id',
  justOne: true
})
UserProgressSchema.virtual("sub_category", {
  ref: 'SubCategory',
  localField: 'sub_category_id',
  foreignField: '_id',
  justOne: true
})
UserProgressSchema.virtual("user", {
  ref: 'User',
  localField: 'user_id',
  foreignField: '_id',
  justOne: true
})

UserProgressSchema.post(["find", 'update', 'updateMany'], handleURL);
UserProgressSchema.post("aggregate", handleURL);
UserProgressSchema.post(["findOne", "findOneAndUpdate", "updateOne"], handleSingleURL);
UserProgressSchema.post("save", handleSingleURL);

async function handleURL(values) {
  values.map(async (item) => item.thumbnail_url = await signURL(item.thumbnail_url));
  return values;
}

async function handleSingleURL(value) {
  if (!value) return;
  value.thumbnail_url = await signURL(value.thumbnail_url);
  return value;
}

let UserProgressModel = DBOperation.createModel(modelName, UserProgressSchema);
const UserProgress = new SchemaMethods(UserProgressModel);
export default UserProgress;
