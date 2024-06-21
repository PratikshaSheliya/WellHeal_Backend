import { RESOURCE_FORMAT } from "../shared/constant/types.const.js";
import DBOperation from "../shared/services/database/database_operation.service.js";
import SchemaMethods from "../shared/services/database/schema_methods.service.js";
import { signURL } from "../shared/services/file-upload/aws-s3.service.js";

// mongoose schema
const schema = {
  name: {
    type: String,
    required: true,
    trim: true,
    default: "",
  },
  description: {
    type: String,
    required: false,
    trim: true,
    default: "",
  },
  session_counts: {
    type: Number,
    required: true,
    default: 1,
  },
  thumbnail_url: {
    type: String,
    required: false,
    trim: true,
    default: "",
  },
  duration: {
    type: String,
    required: true,
    default: "",
  },
  format: {
    type: Number,   /* 1 : video, 2: audio */
    required: true,
    default: 1,
    enum: [RESOURCE_FORMAT.VIDEO, RESOURCE_FORMAT.AUDIO]
  },
  status: {
    type: Number,
    required: true,
    default: 1,
  },
  is_upcomming: {
    type: Boolean,
    required: false,
    default: false
  },
  percentage: {
    type: Number,
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
const modelName = "Therapy";
const TherapySchema = DBOperation.createSchema(modelName, schema);
TherapySchema.post(["find", 'update', 'updateMany'], handleURL);
TherapySchema.post("aggregate", handleURL);
TherapySchema.post(["findOne", "findOneAndUpdate", "updateOne"], handleSingleURL);
TherapySchema.post("save", handleSingleURL);

async function handleURL(values) {
  values.map(async (item) => item.thumbnail_url = await signURL(item.thumbnail_url));
  return values;
}

async function handleSingleURL(value) {
  if (!value) return;
  value.thumbnail_url = await signURL(value.thumbnail_url);
  return value;
}

let TherapyModel = DBOperation.createModel(modelName, TherapySchema);
const Therapy = new SchemaMethods(TherapyModel);
export default Therapy;
