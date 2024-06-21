import mongoose from "mongoose";
import { signURL } from "../shared/services/file-upload/aws-s3.service.js";
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
  thumbnail_url: {
    type: String,
    required: false,
    trim: true,
    default: "",
  },
  thumbnail_url2: {
    type: String,
    required: false,
    trim: true,
    default: "",
  },
  affirmationzoneimge: {
    type: String,
    required: false,
    trim: true,
    default: "",
  },
  category_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Category",
    required: true,
    trim: true,
    autopopulate: true
  },
  sub_category_code: {
    type: String,
    required: true,
    trim: true,
    unique: true,
  },
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
    default: null
  }
};


const modelName = "SubCategory";
const SubCategorySchema = DBOperation.createSchema(modelName, schema);
SubCategorySchema.virtual("category", {
  ref: 'Category',
  localField: 'category_id',
  foreignField: '_id',
  justOne: true
})

SubCategorySchema.post(["find", 'update', 'updateMany'], handleURL);
SubCategorySchema.post("aggregate", handleURL);
SubCategorySchema.post(["findOne", "findOneAndUpdate", "updateOne"], handleSingleURL);
SubCategorySchema.post("save", handleSingleURL);

async function handleURL(values) {
  values.map(async (item) => item.thumbnail_url = await signURL(item.thumbnail_url));
  values.map(async (item) => item.thumbnail_url2 = await signURL(item.thumbnail_url2));
  values.map(async (item) => item.affirmationzoneimge = await signURL(item.affirmationzoneimge));
  return values;
}

async function handleSingleURL(value) {
  if (!value) return;
  value.thumbnail_url = await signURL(value.thumbnail_url);
  value.thumbnail_url2 = await signURL(value.thumbnail_url2);
  value.affirmationzoneimge = await signURL(value.affirmationzoneimge);
  return value;
}

let SubCategoryModel = DBOperation.createModel(modelName, SubCategorySchema);
const SubCategory = new SchemaMethods(SubCategoryModel);

export default SubCategory;
