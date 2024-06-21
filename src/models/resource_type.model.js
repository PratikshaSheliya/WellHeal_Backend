import mongoose from "mongoose";
import DBOperation from "./../shared/services/database/database_operation.service.js";
import SchemaMethods from "./../shared/services/database/schema_methods.service.js";

// mongoose schema
const schema = {
  type: {
    type: String,
    required: true,
    trim: true,
    default: ""
  },
  sort_index: {
    type: Number,
    required: false,
    trim: true,
    default: 0
  }
};
const modelName = "ResourceType";
const ResourceTypeSchema = DBOperation.createSchema(modelName, schema);
let ResourceTypeModel = DBOperation.createModel(modelName, ResourceTypeSchema);
const ResourceType = new SchemaMethods(ResourceTypeModel);
export default ResourceType;
