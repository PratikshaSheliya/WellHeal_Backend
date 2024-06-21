import mongoose from "mongoose";
import { signURL } from "../shared/services/file-upload/aws-s3.service.js";
import DBOperation from "./../shared/services/database/database_operation.service.js";
import SchemaMethods from "./../shared/services/database/schema_methods.service.js";

// mongoose schema
const schema = {
  question: {
    type: String,
    required: true,
    trim: true,
    default: "",
  },
  question_category: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "SubCategory",
    required: false,
    trim: true
  },
  health_weights: {
    type: JSON,
    required: false,
    trim: true,
    default: {},
  },
  question_type: {
    type: Number,
    required: true
  },
  combination_code_ids: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: "SubCategory",
    autopopulate: true
  }],
  thumbnail_url: {
    type: String,
    required: false,
    trim: true,
    default: "",
  },
  status: {
    type: Number,
    required: true,
    default: 1,
  },
};
const modelName = "Question";
const QuestionSchema = DBOperation.createSchema(modelName, schema);
QuestionSchema.virtual("combination_codes", {
  ref: 'SubCategory',
  localField: 'combination_code_ids',
  foreignField: '_id',
})

QuestionSchema.post(["find", 'update', 'updateMany'], handleURL);
QuestionSchema.post("aggregate", handleURL);
QuestionSchema.post(["findOne", "findOneAndUpdate", "updateOne"], handleSingleURL);
QuestionSchema.post("save", handleSingleURL);

async function handleURL(values) {
  values.map(async (item) => item.thumbnail_url = await signURL(item.thumbnail_url));
  return values;
}

async function handleSingleURL(value) {
  if (!value) return;
  value.thumbnail_url = await signURL(value.thumbnail_url);
  return value;
}

let QuestionModel = DBOperation.createModel(modelName, QuestionSchema);
const Question = new SchemaMethods(QuestionModel);
export default Question;
