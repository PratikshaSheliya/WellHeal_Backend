import mongoose from "mongoose";
import { DEVICE_TYPE } from '../shared/constant/types.const.js';
import DBOperation from '../shared/services/database/database_operation.service.js';
import SchemaMethods from '../shared/services/database/schema_methods.service.js';

// mongoose schema
const schema = {
  user_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
    trim: true,
  },
  device_id: {
    type: String,
    required: true,
    trim: true
  },
  device_token: {
    type: String,
    required: true,
    trim: true
  },
  device_type: {
    type: String, // "I": IOS, "A": Android
    trim: true,
    required: true,
    enum: Object.values(DEVICE_TYPE)
  },
  is_deleted: {
    type: Boolean,
    default: false
  },
  deleted_at: {
    type: Date,
    default: null
  },
  is_loggedOut: {
    type: Boolean,
    default: false
  },
  loggedOut_at: {
    type: Date,
    default: null
  }
};
const modelName = 'UserToken';
const UserTokenSchema = DBOperation.createSchema(modelName, schema);
UserTokenSchema.virtual("user", {
  ref: 'User',
  localField: 'user_id',
  foreignField: '_id',
  justOne: true
})
let UserTokenModel = DBOperation.createModel(modelName, UserTokenSchema);
const UserToken = new SchemaMethods(UserTokenModel);
export default UserToken;