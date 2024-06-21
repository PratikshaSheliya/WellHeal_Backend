import DBOperation from './../shared/services/database/database_operation.service.js';
import SchemaMethods from './../shared/services/database/schema_methods.service.js';
import mongoose from "mongoose";

// mongoose schema
const schema = {
  image: {
    type: String,
    required: false,
    default: ''
  },
  description: {
    type: String,
    default: ''
  },
  user_ids: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
    trim: true,
  }],
  schedule: {
    type: Date,
    default: null,
    required: true,
  }
};
const modelName = 'Quote';
const QuoteSchema = DBOperation.createSchema(modelName, schema);
let QuoteModel = DBOperation.createModel(modelName, QuoteSchema);
const Quote = new SchemaMethods(QuoteModel);
export default Quote;