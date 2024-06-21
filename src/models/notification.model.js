import mongoose from "mongoose";
import DBOperation from "../shared/services/database/database_operation.service.js";
import SchemaMethods from "../shared/services/database/schema_methods.service.js";
import { signURL } from "../shared/services/file-upload/aws-s3.service.js";
import { encrypt, decrypt } from "../shared/utils/utility.js";

// mongoose schema
const schema = {
  user_ids: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
    trim: true,
  }],
  schedule_time: {
    type: Date,
    default: null
  },
  title: {
    type: String,
    required: false,
    default: "",
  },
  description: {
    type: String,
    required: false,
    default: "",
  },
  image: {
    type: String,
    required: false,
    default: "",
  }
};
const modelName = "Notification";
const NotificationSchema = DBOperation.createSchema(modelName, schema);

NotificationSchema.post(["find", 'update', 'updateMany'], handleURL);
NotificationSchema.post("aggregate", handleURL);
NotificationSchema.post(["findOne", "findOneAndUpdate", "updateOne"], handleSingleURL);
NotificationSchema.post("save", handleSingleURL);
NotificationSchema.virtual("user", {
  ref: 'User',
  localField: 'user_ids',
  foreignField: '_id',
  justOne: true
})

async function handleURL(values) {
  values.map(async (item) => item.url = await signURL(item.url));
  return values;
}

async function handleSingleURL(value) {
  if (!value) return;
  value.url = await signURL(value.url);
  return value;
}



let NotificationModel = DBOperation.createModel(modelName, NotificationSchema);
const Notification = new SchemaMethods(NotificationModel);
export default Notification;
