import { REFERRER_TYPE } from "../shared/constant/types.const.js";
import DBOperation from "../shared/services/database/database_operation.service.js";
import SchemaMethods from "../shared/services/database/schema_methods.service.js";
import mongoose from "mongoose";

// mongoose schema
const schema = {
  referrer: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
    trim: true,
  },
  referee: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
    trim: true,
  },
  refer_type: {
    type: Number,
    enum: [...Object.values(REFERRER_TYPE)]
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

const modelName = "ReferUser";
const ReferUserSchema = DBOperation.createSchema(modelName, schema);
ReferUserSchema.virtual("user", {
  ref: 'User',
  localField: 'user_id',
  foreignField: '_id',
  justOne: true
})

let ReferUserModel = DBOperation.createModel(modelName, ReferUserSchema);
const ReferUser = new SchemaMethods(ReferUserModel);
export default ReferUser;
