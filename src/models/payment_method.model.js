import DBOperation from './../shared/services/database/database_operation.service.js';
import SchemaMethods from './../shared/services/database/schema_methods.service.js';
import mongoose from "mongoose";

const schema = {
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true,
        trim: true,
    },
    type: {
        type: String,
        required: true,
        default: null
    },
    payment_Method_id: {
        type: String,
        required: true,
        default: null
    },
};

const modelName = 'PaymentMethod';
const PaymentSchema = DBOperation.createSchema(modelName, schema);

let PaymentModel = DBOperation.createModel(modelName, PaymentSchema);
const PaymentMethod = new SchemaMethods(PaymentModel);
export default PaymentMethod;
