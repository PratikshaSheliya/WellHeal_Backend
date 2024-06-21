import mongoose from "mongoose";
import DBOperation from './../shared/services/database/database_operation.service.js';
import SchemaMethods from './../shared/services/database/schema_methods.service.js';

const schema = {
  plan_type: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "SubscribePaymentCard",
    trim: true,
    default: null,
  },
  googlePayId: {
    type: String,
    trim: true,
    default: null,
  },
  applePayId: {
    type: String,
    trim: true,
    default: null,
  },
  priceId: {
    type: String,
    trim: true,
    default: null,
  },
  subscribeScheduleId: {
    type: String,
    trim: true,
    default: null,
  },
  subscribeId: {
    type: String,
    trim: true,
    default: null,
  },
  priceDetail: {
    type: Object,
    trim: true,
    default: null,
  },
  current_phase: {
    type: Object,
    trim: true,
    default: null,
  },
  expiry_time: {
    type: Date,
    trim: true,
    default: null,
  },
  payment_id: {
    type: String,
    trim: true,
    default: null,
  },
  paymentDetail: {
    type: Object,
    trim: true,
    default: null,
  },
  order_id: {
    type: String,
    trim: true,
    default: null,
  },
  signature: {
    type: String,
    trim: true,
    default: null,
  },
  user_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    trim: true,
    default: null,
  },
  is_schedule: {
    type: Boolean,
    required: false,
    default: false,
  },
  is_deleted: {
    type: Boolean,
    default: false,
  },
  deleted_at: {
    type: Date,
    default: null,
  },
};

const modelName = 'Payment';
const PaymentSchema = DBOperation.createSchema(modelName, schema);

let PaymentModel = DBOperation.createModel(modelName, PaymentSchema);
const Payment = new SchemaMethods(PaymentModel);
export default Payment;
