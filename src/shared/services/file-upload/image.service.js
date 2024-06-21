import { v1 as uuidv1 } from 'uuid';
import { createWriteStream } from 'fs';
import { pipeline } from 'stream';
import { promisify } from 'util'
import got from 'got';
import multer from 'multer';
import * as fs from 'fs';
import path from 'path';
import logger, { level } from '../../../config/logger.js';
import { MAX_FILE_SIZE } from '../../constant/file_upload.const';

// const uploadPath = './src/assets/tmp';

// Use __dirname : because if we use static path like above, 
// this image service is running in server from dist folder. 
// So if we used ./src/... path then, it will upload file inside src folder which is outside of dist in server.
//  So when we serve static file, at that time it will find that image into dist's asset folder where image will not available 
// because file is uploaded outside of dist.

// So for solution, we need dist's assets folder.
// __dirname will return a current file's path (which is in dist where code is running)

// final path of upload is like this : D:\node\Service Based\Template-Market\dist\assets\tmp
const uploadPath = path.join(__dirname, "../..", 'assets', 'tmp');
const allowed_file_types = ['image/jpg', 'image/jpeg', 'image/png', 'image/webp', 'application/zip', 'application/x-zip-compressed', 'application/gzip', 'application/x-7z-compressed']

const storage = multer.diskStorage({
  destination: async function (_req, _file, cb) {
    await createDirectoryPath(uploadPath);
    cb(null, uploadPath)
  },

  filename: function (_req, file, cb) {
    const extension = file.originalname.substring(file.originalname.lastIndexOf('.') + 1, file.originalname.length)
    let uuid = uuidv1();
    cb(null, `${Date.now()}-${uuid}.${extension}`)
  }
});

const fileFilter = (req, file, cb) => {
  // const fileSize = parseInt(req.headers['content-length']);
  if (allowed_file_types.indexOf(file.mimetype) != -1) {
    // if (fileSize <= MAX_FILE_SIZE)
    cb(null, true);
    // else {
    //   cb(new Error(`File is larger then ${MAX_FILE_SIZE / (1024 * 1024)}MB`), false);
    // }
  } else {
    cb(new Error("File is not of type jpg/jpeg, png, zip, webp"), false);
  }
}

export const Upload = multer({ storage: storage, fileFilter: fileFilter, limits: { fileSize: MAX_FILE_SIZE } });

export const createDirectoryPath = (uploadPath) => {
  try {
    if (!fs.existsSync(uploadPath)) {
      fs.mkdirSync(uploadPath)
    }
  } catch (error) {
    logger.log(level.error, `Image Service createDirectoryPath path=${uploadPath}`)
    throw Error(error)
  }
}

export const uploadImageFromURL = async (url, destination) => {
  logger.log(level.error, `Image Service uploadImageFromURL: url=${url}`);
  try {
    if (url) {
      let uuid = uuidv1();
      const streamPipeline = promisify(pipeline);
      let name = `${Date.now()}_image_${uuid}.png`;
      const downloadStream = await got.stream(url);
      createDirectoryPath(destination);
      return await streamPipeline(downloadStream, createWriteStream(destination + name)).then(() => {
        logger.log(level.info, `file saved into server`)
        return { name, path: destination, image_url: destination + name };
      });
    } else {
      return { name: '', path: '', image_url: '' };
    }
  } catch (error) {
    logger.log(level.error, `Image Service uploadImageFromURL: error=${error}`);
    return { name: '', path: '', image_url: '' };
  }
}