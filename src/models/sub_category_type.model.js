import mongoose from "mongoose";
import DBOperation from "./../shared/services/database/database_operation.service.js";
import SchemaMethods from "./../shared/services/database/schema_methods.service.js";

// mongoose schema
const schema = {
  sub_category_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "SubCategory",
    required: true,
    trim: true,
  },
  type: {
    type: String,
    trim: true,
    default: "",
  },
};
const modelName = "SubCategoryType";
const SubCategoryTypeSchema = DBOperation.createSchema(modelName, schema);
SubCategoryTypeSchema.virtual("sub_category", {
  ref: 'SubCategory',
  localField: 'sub_category_id',
  foreignField: '_id',
  justOne: true
})
let SubCategoryTypeModel = DBOperation.createModel(modelName, SubCategoryTypeSchema);
const SubCategoryType = new SchemaMethods(SubCategoryTypeModel);
export default SubCategoryType;
