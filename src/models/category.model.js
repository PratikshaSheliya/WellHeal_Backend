import DBOperation from './../shared/services/database/database_operation.service.js';
import SchemaMethods from './../shared/services/database/schema_methods.service.js';

// mongoose schema
const schema = {
  name: {
    type: String,
    required: true,
    trim: true,
    default: ''
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
const modelName = 'Category';
const CategorySchema = DBOperation.createSchema(modelName, schema);
let CategoryModel = DBOperation.createModel(modelName, CategorySchema);
const Category = new SchemaMethods(CategoryModel);
export default Category;