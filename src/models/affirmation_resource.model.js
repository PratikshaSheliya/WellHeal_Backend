import mongoose from "mongoose";
import DBOperation from "../shared/services/database/database_operation.service.js";
import SchemaMethods from "../shared/services/database/schema_methods.service.js";
import { signURL } from "../shared/services/file-upload/aws-s3.service.js";

// mongoose schema
const schema = {
  resource_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Resource",
    required: true,
    trim: true,
  },
  sub_category_id: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: "SubCategory"
  }],
  is_deleted: {
    type: Boolean,
    default: false
  },
  deleted_at: {
    type: Date,
    default: null
  }
};
const modelName = "AffirmationResource";
const AffirmationResourceSchema = DBOperation.createSchema(modelName, schema);

AffirmationResourceSchema.post(["find", 'update', 'updateMany'], handleURL);
AffirmationResourceSchema.post("aggregate", handleURL);
AffirmationResourceSchema.post(["findOne", "findOneAndUpdate", "updateOne"], handleSingleURL);
AffirmationResourceSchema.post("save", handleSingleURL);

async function handleURL(values) {
  await Promise.all(values.map(async (item) => {
    item.thumbnail_url = await signURL(item.thumbnail_url)
    item.url = await signURL(item.url)

    if(item.sub_category !== undefined){
        await Promise.all(item.sub_category.map(async(subcategory) => {
                subcategory.thumbnail_url  = await signURL(subcategory.thumbnail_url);
                subcategory.thumbnail_url2 = await signURL(subcategory.thumbnail_url2);
                subcategory.affirmationzoneimge = await signURL(subcategory.affirmationzoneimge);
              }
            )
        )
      }
  }));
  return values;
}

async function handleSingleURL(value) {
  if (!value) return;
  value.thumbnail_url = await signURL(value.thumbnail_url);
  value.url = await signURL(value.url);
  return value;
}

AffirmationResourceSchema.virtual("resource", {
  ref: 'Resource',
  localField: 'resource_id',
  foreignField: '_id',
  justOne: true
})

AffirmationResourceSchema.virtual("sub_category", {
  ref: 'SubCategory',
  localField: 'sub_category_id',
  foreignField: '_id'
})

let ResourceModel = DBOperation.createModel(modelName, AffirmationResourceSchema);
const AffirmationResource = new SchemaMethods(ResourceModel);
export default AffirmationResource;
