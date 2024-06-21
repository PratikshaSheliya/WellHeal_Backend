import mongoose from "mongoose";
import DBOperation from "../shared/services/database/database_operation.service.js";
import SchemaMethods from "../shared/services/database/schema_methods.service.js";

// mongoose schema
const schema = {
    user_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
    trim: true,
  },
    /* userTrial: {
    type: Boolean,
    trim: true,
    //default: false, // Default value is set to false
    }, */
    startTrial: {
    type: Date,
    trim: true,
    },
    endTrial: {
    type: Date,
    trim: true,
    },
};
const modelName = "trialusers";
const TrialUsersSchema = DBOperation.createSchema(modelName, schema);
let TrialUsersModel = DBOperation.createModel(modelName, TrialUsersSchema);
const TrialUsers = new SchemaMethods(TrialUsersModel);
export default TrialUsers;
