import mongoose from "mongoose";
import { signURL } from "../shared/services/file-upload/aws-s3.service.js";
import DBOperation from "./../shared/services/database/database_operation.service.js";
import SchemaMethods from "./../shared/services/database/schema_methods.service.js";
// mongoose schema
const schema = {
  therapy_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Therapy",
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
const modelName = "SubCategoryTherapy";
const SubCategoryTherapySchema = DBOperation.createSchema(modelName, schema);
SubCategoryTherapySchema.virtual("therapy", {
  ref: 'Therapy',
  localField: 'therapy_id',
  foreignField: '_id',
  justOne: true
})
SubCategoryTherapySchema.virtual("sub_category", {
  ref: 'SubCategory',
  localField: 'sub_category_id',
  foreignField: '_id'
})

SubCategoryTherapySchema.post(["find", 'update', 'updateMany'], handleURL);
SubCategoryTherapySchema.post("aggregate", handleURL);
SubCategoryTherapySchema.post(["findOne", "findOneAndUpdate", "updateOne"], handleSingleURL);
SubCategoryTherapySchema.post("save", handleSingleURL);

async function handleURL(values) {
   /*old code 
  values.map(async (item) => {
    item.thumbnail_url = await signURL(item.thumbnail_url);
  }) */
  if(values.length>0){
    let subcategoryId;
    values.forEach((item) => {
      if (item.sub_category && item.sub_category.subcategory_id) {
        subcategoryId = item.sub_category.subcategory_id;
      }
    });
    
    if (subcategoryId) {
      await Promise.all(
        values.map(async (item) => {
          item.therapy.thumbnail_url = await signURL(item.therapy.thumbnail_url);
          item.sub_category.thumbnail_url = await signURL(item.sub_category.thumbnail_url);
          item.sub_category.thumbnail_url2 = await signURL(item.sub_category.thumbnail_url2);
          item.sub_category.affirmationzoneimge = await signURL(item.sub_category.affirmationzoneimge);
        })
      );
    } else {
      await Promise.all(
        values.map(async (item) => {
          item.thumbnail_url = await signURL(item.thumbnail_url);
        })
      );
    }
    return values;
  }
}

async function handleSingleURL(value) {
  if (!value) return;
  value.thumbnail_url = await signURL(value.thumbnail_url);
  return value;
}


let SubCategoryModelTherapy = DBOperation.createModel(modelName, SubCategoryTherapySchema);
const SubCategoryTherapy = new SchemaMethods(SubCategoryModelTherapy);
export default SubCategoryTherapy;
