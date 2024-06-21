import DBOperation from './../shared/services/database/database_operation.service.js';
import SchemaMethods from './../shared/services/database/schema_methods.service.js';

const schema = {
    month: {
        type: String,
        required: true,
        default: ''
    },
    price: {
        type: String,
        required: true,
        default: ''
    },
    recommended: {
        type: Boolean,
        default: false
    }
};

const modelName = 'SubscribePaymentCard';
const SubscribePaymentCardSchema = DBOperation.createSchema(modelName, schema);
let SubscribePaymentCardModel = DBOperation.createModel(modelName, SubscribePaymentCardSchema);
const SubscribePaymentCard = new SchemaMethods(SubscribePaymentCardModel);
export default SubscribePaymentCard;