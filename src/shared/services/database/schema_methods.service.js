import DBOperation from "./database_operation.service.js";
import { logger, level } from "./../../../config/logger.js";

export default class SchemaMethods {
  constructor(model) {
    this.model = model;
  }

  async add(inputData) {
    return new Promise((resolve, reject) => {
      try {
        const newDoc = Promise.resolve(
          DBOperation.create(this.model, inputData)
        );
        resolve(newDoc);
      } catch (err) {
        reject(err);
      }
    });
  }

  async isExist(filter, option) {
    let isExist = false;
    try {
      const doc = await DBOperation.get(this.model, filter, null, option);
      if (doc.length > 0) {
        isExist = true;
      }
    } catch (err) {
      logger.log(level.error, err);
    }
    return isExist;
  }

  async get(filter, returnField = null, option = null, populate = null) {
    return new Promise((resolve, reject) => {
      try {
        const docs = Promise.resolve(
          DBOperation.get(this.model, filter, returnField, option, populate)
        );
        resolve(docs);
      } catch (err) {
        reject(err);
      }
    });
  }

  async count(filter, option = null) {
    return new Promise((resolve, reject) => {
      try {
        const count = Promise.resolve(
          DBOperation.getCount(this.model, filter, option)
        );
        resolve(count);
      } catch (err) {
        reject(err);
      }
    });
  }

  async update(filter, updatedField, populate = null) {
    return new Promise((resolve, reject) => {
      try {
        const updatedDoc = Promise.resolve(DBOperation.update(this.model, filter, updatedField, populate));
        resolve(updatedDoc);
      } catch (err) {
        reject(err);
      }
    });
  }

  async upsert(filter, updatedField, populate = null) {
    return new Promise((resolve, reject) => {
      try {
        const updatedDoc = Promise.resolve(DBOperation.upsert(this.model, filter, updatedField, populate));
        resolve(updatedDoc);
      } catch (err) {
        reject(err);
      }
    });
  }

  async updateMany(filter, updatedField) {
    return new Promise((resolve, reject) => {
      try {
        const updatedDocs = Promise.resolve(
          DBOperation.updateMany(this.model, filter, updatedField)
        );
        resolve(updatedDocs);
      } catch (err) {
        reject(err);
      }
    });
  }

  async delete(filter) {
    return new Promise((resolve, reject) => {
      try {
        const deletedDoc = Promise.resolve(
          DBOperation.delete(this.model, filter)
        );
        resolve(deletedDoc);
      } catch (err) {
        reject(err);
      }
    });
  }

  async deleteMany(filter) {
    return new Promise((resolve, reject) => {
      try {
        const deletedDocs = Promise.resolve(
          DBOperation.deleteMany(this.model, filter)
        );
        resolve(deletedDocs);
      } catch (err) {
        reject(err);
      }
    });
  }

  async aggregate(pipeline) {
    return new Promise((resolve, reject) => {
      try {
        const data = Promise.resolve(
          DBOperation.aggregate(this.model, pipeline)
        );
        resolve(data);
      } catch (err) {
        reject(err);
      }
    });
  }

  async distinct(field, condition) {
    return new Promise((resolve, reject) => {
      try {
        const data = Promise.resolve(
          DBOperation.distinct(this.model, field, condition)
        );
        resolve(data);
      } catch (err) {
        reject(err);
      }
    });
  }
}