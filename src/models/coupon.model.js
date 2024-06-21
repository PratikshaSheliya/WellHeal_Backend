import mongoose from 'mongoose';
import { COUPON_FOR_WHO, COUPON_TYPE, DISCOUNT_TYPE } from '../shared/constant/types.const.js';
import DBOperation from './../shared/services/database/database_operation.service.js';
import SchemaMethods from './../shared/services/database/schema_methods.service.js';

// mongoose schema
const schema = {
  user_id: {
    type: mongoose.Schema.Types.ObjectId,
    required: false,
    ref: "User"
  },
  coupon_type: {
    type: Number,
    required: true,
    trim: true,
    enum: Object.values(COUPON_TYPE)
  },
  coupon_code: {
    type: String,
    required: true,
    trim: true,
    default: ''
  },
  coupon_for: {
    type: Number,
    trim: true,
    enum: Object.values(COUPON_FOR_WHO)
  },
  expire_time: {
    type: Number,
    required: false,
    trim: true,
  },
  discount_type: {
    type: Number,
    required: false,
    trim: true,
    enum: Object.values(DISCOUNT_TYPE)
  },
  discount_amount: {
    type: Number,
    required: false,
    trim: true,
  },
  discount_percentage: {
    type: Number,
    required: false,
    trim: true,
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
const modelName = 'Coupon';
const CouponSchema = DBOperation.createSchema(modelName, schema);
CouponSchema.virtual("user", {
  ref: 'User',
  localField: 'user_id',
  foreignField: '_id',
  justOne: true
})

let CouponModel = DBOperation.createModel(modelName, CouponSchema);
const Coupon = new SchemaMethods(CouponModel);
export default Coupon;