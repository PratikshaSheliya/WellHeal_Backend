import mongoose from "mongoose";
import { FAVORITE_CONTENT_TYPE } from "../shared/constant/types.const.js";
import DBOperation from "../shared/services/database/database_operation.service.js";
import SchemaMethods from "../shared/services/database/schema_methods.service.js";

// mongoose schema
const schema = {
  content_type: {
    type: String,
    enum: [FAVORITE_CONTENT_TYPE.THERAPY, FAVORITE_CONTENT_TYPE.RESOURCE]
  },
  favourite_id: {
    type: mongoose.Schema.Types.ObjectId,
    refPath: 'model_type'
  },
  model_type: {
    type: String,
    enum: [FAVORITE_CONTENT_TYPE[FAVORITE_CONTENT_TYPE.THERAPY], FAVORITE_CONTENT_TYPE[FAVORITE_CONTENT_TYPE.RESOURCE]]
  },
  user_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
    trim: true,
  },
};
const modelName = "Favorites";
const FavoriteSchema = DBOperation.createSchema(modelName, schema);
FavoriteSchema.virtual("user", {
  ref: 'User',
  localField: 'user_id',
  foreignField: '_id',
  justOne: true
})
FavoriteSchema.virtual("favourite", {
  refPath: 'model_type',
  localField: 'favourite_id',
  foreignField: '_id',
  justOne: true
})

let FavoritesModel = DBOperation.createModel(modelName, FavoriteSchema);
const Favorites = new SchemaMethods(FavoritesModel);
export default Favorites;
