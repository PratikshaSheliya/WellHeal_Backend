import DBOperation from '../shared/services/database/database_operation.service.js';
import SchemaMethods from '../shared/services/database/schema_methods.service.js';

// mongoose schema
const schema = {
    device_id: {
        type: String,
        required: true,
        trim: true
      },
};
const modelName = 'UserDevices';
const UserDevicesSchema = DBOperation.createSchema(modelName, schema);

let UserDevicesModel = DBOperation.createModel(modelName, UserDevicesSchema);
const UserDevices = new SchemaMethods(UserDevicesModel);
export default UserDevices;