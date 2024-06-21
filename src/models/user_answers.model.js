import mongoose from "mongoose";
import DBOperation from "./../shared/services/database/database_operation.service.js";
import SchemaMethods from "./../shared/services/database/schema_methods.service.js";

// mongoose schema
const schema = {
  question_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Question",
    required: true,
    trim: true,
  },
  question_answer: {
    type: Boolean,
    required: true,
    trim: true
  },
  user_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
    trim: true,
  },
};
const modelName = "UserAnswers";
const UserAnswerSchema = DBOperation.createSchema(modelName, schema);
UserAnswerSchema.virtual("question", {
  ref: 'Question',
  localField: 'question_id',
  foreignField: '_id',
  justOne: true
})
UserAnswerSchema.virtual("user", {
  ref: 'User',
  localField: 'user_id',
  foreignField: '_id',
  justOne: true
})
let UserAnswersModel = DBOperation.createModel(modelName, UserAnswerSchema);
const UserAnswers = new SchemaMethods(UserAnswersModel);
export default UserAnswers;
