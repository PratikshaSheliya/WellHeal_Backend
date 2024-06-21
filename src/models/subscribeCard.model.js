import DBOperation from './../shared/services/database/database_operation.service.js';
import SchemaMethods from './../shared/services/database/schema_methods.service.js';

const schema = {
    image: {
        type: String,
        required: false,
        default: ''
    },
    description: {
        type: String,
        required: true,
        default: ''
    },
    title: {
        type: String,
        default: null,
        required: true,
    }
};

const modelName = 'SubscribeCard';
const SubscribeCardSchema = DBOperation.createSchema(modelName, schema);
let SubscribeCardModel = DBOperation.createModel(modelName, SubscribeCardSchema);
const SubscribeCard = new SchemaMethods(SubscribeCardModel);
export default SubscribeCard;