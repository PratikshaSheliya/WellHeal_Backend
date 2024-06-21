import mongoose from "mongoose";
import { signURL } from "../shared/services/file-upload/aws-s3.service.js";
import DBOperation from "./../shared/services/database/database_operation.service.js";
import SchemaMethods from "./../shared/services/database/schema_methods.service.js";

// mongoose schema
const schema = {
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
};
const modelName = "TherapyProgress";
const TherapyProgressSchema = DBOperation.createSchema(modelName, schema);
TherapyProgressSchema.virtual("therapy", {
  ref: 'Therapy',
  localField: 'therapy_id',
  foreignField: '_id',
  justOne: true
})
TherapyProgressSchema.virtual("sub_category", {
  ref: 'SubCategory',
  localField: 'sub_category_id',
  foreignField: '_id',
  justOne: true
})
TherapyProgressSchema.virtual("user", {
  ref: 'User',
  localField: 'user_id',
  foreignField: '_id',
  justOne: true
})

TherapyProgressSchema.post(["find", 'update', 'updateMany'], handleURL);
TherapyProgressSchema.post("aggregate", handleURL);
TherapyProgressSchema.post(["findOne", "findOneAndUpdate", "updateOne"], handleSingleURL);
TherapyProgressSchema.post("save", handleSingleURL);

async function handleURL(values) {
  values.map(async (item) => item.thumbnail_url = await signURL(item.thumbnail_url));
  return values;
}

async function handleSingleURL(value) {
  if (!value) return;
  value.thumbnail_url = await signURL(value.thumbnail_url);
  return value;
}

let TherapyProgressModel = DBOperation.createModel(modelName, TherapyProgressSchema);
const TherapyProgress = new SchemaMethods(TherapyProgressModel);
export default TherapyProgress;
