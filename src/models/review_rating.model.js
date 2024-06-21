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
  rating: {
    type: Number,
    required: true,
    default: 0
  },
  review: {
    type: String,
    required: false,
    trim: true
  },
  resource_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Resource",
    trim: true,
  },
  therapy_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Therapy",
    trim: true,
  }
};
const modelName = "ReviewRating";
const ReviewRatingSchema = DBOperation.createSchema(modelName, schema);
ReviewRatingSchema.virtual("user", {
  ref: 'User',
  localField: 'user_id',
  foreignField: '_id',
  justOne: true
})
ReviewRatingSchema.virtual("resource", {
  ref: 'Resource',
  localField: 'resource_id',
  foreignField: '_id',
  justOne: true
})
ReviewRatingSchema.virtual("therapy", {
  ref: 'Therapy',
  localField: 'therapy_id',
  foreignField: '_id',
  justOne: true
})

let ReviewRatingModel = DBOperation.createModel(modelName, ReviewRatingSchema);
const ReviewRating = new SchemaMethods(ReviewRatingModel);
export default ReviewRating;
