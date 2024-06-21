import mongoose from "mongoose";
import DBOperation from "../shared/services/database/database_operation.service.js";
import SchemaMethods from "../shared/services/database/schema_methods.service.js";

const schema = {
    user_ids: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true,
        trim: true,
    }],
    schedule_time: {
        type: Date,
        default: null
    },
    isSchedule: {
        type: Boolean,
        required: true,
    },
    isSend: {
        type: Boolean,
        required: false,
    },
    title: {
        type: String,
        required: false,
        default: "",
    },
    description: {
        type: String,
        required: false,
        default: "",
    },
    image: {
        type: String,
        required: false,
        default: "",
    }
};
const modelName = "scheduleNotification";
const NotificationSchema = DBOperation.createSchema(modelName, schema);

NotificationSchema.virtual("user", {
    ref: 'User',
    localField: 'user_ids',
    foreignField: '_id',
    justOne: true
});

let NotificationModel = DBOperation.createModel(modelName, NotificationSchema);
const scheduleNotification = new SchemaMethods(NotificationModel);
export default scheduleNotification;
