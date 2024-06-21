import { Schema, model } from 'mongoose';
import { replace_Id } from '../../utils/utility.js';
import { logger, level } from './../../../config/logger.js';
const timestamps = { createdAt: 'created_at', updatedAt: 'updated_at' };
// database class for crud operation
class DatabaseOperation {

  createSchema(modelName, schema) {
    try {
      return new Schema(schema, {
        timestamps,
        toJSON: {
          virtuals: true,
          getters: true,
          setters: true,
          transform: function (doc, ret) {
            ret[`${modelName.toLowerCase()}_id`] = ret._id;
            delete ret._id;
            delete ret.id;
          }
        },
        toObject: {
          getters: true
        }
      });
    } catch (e) {
      logger.log(level.error, e);
    }
  }

  // create monogoDB model
  createModel(modelName, schema) {
    try {
      return model(modelName, schema);
    } catch (e) {
      logger.log(level.error, e);
    }
  }

  // create new document
  async create(modelClass, obj) {
    const model = new modelClass(obj);
    return new Promise((resolve, reject) => {
      try {
        const data = Promise.resolve(model.save());
        resolve(data);
      } catch (err) {
        reject(err);
      }
    });
  }

  // retrive document
  async get(modelClass, filter, returnField, option, populate) {
    return new Promise(async (resolve, reject) => {
      const opArgs = {};
      option && option.offset ? (opArgs.skip = option.offset) : '';
      option && option.limit ? (opArgs.limit = option.limit) : '';
      option && option.sort ? (opArgs.sort = option.sort) : '';
      option && option.collation ? (opArgs.collation = option.collation) : '';
      try {
        let doc = modelClass.find(filter, returnField, opArgs);
        if (populate)
          doc = doc.populate(populate);

        const data = Promise.resolve(doc);
        resolve(data || []);
      } catch (err) {
        reject(err);
      }
    });
  }

  // retrive document count
  async getCount(modelClass, filter, option) {
    return new Promise((resolve, reject) => {
      const opArgs = {};
      option && option.offset ? (opArgs.skip = option.offset) : '';
      option && option.limit ? (opArgs.limit = option.limit) : '';
      option && option.sort ? (opArgs.sort = option.sort) : '';
      try {
        const data = Promise.resolve(
          modelClass.find(filter, null, opArgs).countDocuments()
        );
        resolve(data);
      } catch (err) {
        reject(err);
      }
    });
  }

  // update document
  async update(modelClass, filter, updatedField, populate) {
    const option = {
      new: true, // return updated doc
      runValidators: true // validate before update
    };
    return new Promise((resolve, reject) => {
      try {
        let doc = modelClass.findOneAndUpdate(filter, updatedField, option)
        if (populate)
          doc = doc.populate(populate);

        let data = Promise.resolve(doc);
        resolve(data);
      } catch (err) {
        reject(err);
      }
    });
  }

  async upsert(modelClass, filter, updatedField, populate) {
    const option = {
      new: true, // return updated doc
      runValidators: true, // validate before update
      upsert: true
    };
    return new Promise((resolve, reject) => {
      try {
        let doc = modelClass.findOneAndUpdate(filter, updatedField, option)
        if (populate)
          doc = doc.populate(populate);

        let data = Promise.resolve(doc);
        resolve(data);
      } catch (err) {
        reject(err);
      }
    });
  }

  // update many document
  async updateMany(modelClass, filter, updatedField) {
    const option = {
      new: true, // return updated doc
    };
    return new Promise((resolve, reject) => {
      try {
        const data = Promise.resolve(
          modelClass.updateMany(filter, updatedField, option)
        );
        resolve(data);
      } catch (err) {
        reject(err);
      }
    });
  }

  // delete document
  async delete(modelClass, filter) {
    return new Promise((resolve, reject) => {
      try {
        const data = Promise.resolve(modelClass.findOneAndRemove(filter));
        resolve(data);
      } catch (err) {
        reject(err);
      }
    });
  }

  // delete many document
  async deleteMany(modelClass, filter) {
    return new Promise((resolve, reject) => {
      try {
        const data = Promise.resolve(modelClass.deleteMany(filter));
        resolve(data);
      } catch (err) {
        reject(err);
      }
    });
  }

  // agreegate document
  async aggregate(modelClass, pipeline) {
    try {
      let data = await modelClass.aggregate(pipeline).exec();
      data = replace_Id(data);
      //logger.log(level.debug, `aggregate = ${JSON.stringify(data)}`);
      return data;
    } catch (err) {
      logger.log(level.error, `aggregate err=${err}}`);
    }
  }

  //Distinct document
  async distinct(modelClass, field, condition) {
    try {
      const data = await modelClass.distinct(field, condition).exec();
      logger.log(level.debug, `distinct = ${JSON.stringify(data)}`);
      return data;
    } catch (err) {
      logger.log(level.error, `distinct err=${err}}`);
    }
  }
}
export default new DatabaseOperation();