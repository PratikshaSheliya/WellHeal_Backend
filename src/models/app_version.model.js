import DBOperation from "../shared/services/database/database_operation.service.js";
import SchemaMethods from "../shared/services/database/schema_methods.service.js";

// mongoose schema
const schema = {
  androidVersion: {
    type: String,
    trim: true,
  },
  iOSVersion: {
    type: String,
    unique: true,
    trim: true,
  },
  androidForceUpdate: {
    type: Number,
    trim: true,
  },
  iOSForceUpdate: {
    type: Number,
    trim: true,
  },
};
const modelName = "appversions";
const AppversionSchema = DBOperation.createSchema(modelName, schema);
let AppversionModel = DBOperation.createModel(modelName, AppversionSchema);
const Appversion = new SchemaMethods(AppversionModel);
export default Appversion;
