import AWS from "aws-sdk";
import fs from 'fs';
import logger, {level} from "../../../config/logger.js";
import {beautify} from "../../utils/utility.js";
import Path from "path";

const __dirname = Path.resolve();

const pathName = Path.join(__dirname, "src", "shared", "services", "file-upload", `/Private_key.pem`);
const privateKey = fs.readFileSync(pathName);

AWS.config.update({
  accessKeyId: process.env.Aws_S3_Access_key_id,
  secretAccessKey: process.env.Aws_S3_Secret_Access_key,
  region: process.env.Aws_Region
});

// const signer = new AWS.CloudFront.Signer(process.env.Aws_cloudFront_Access_Key, privateKey);

const S3 = new AWS.S3();

export const uploadFileToS3 = async (bucket, key, file, acl = null) => {
  const options = {
    Bucket: bucket,
    Key: key,
    Body: file.buffer,
    ContentType: file.mimetype
  }
  logger.log(level.debug, `file-option : ContentType=${options.ContentType}, key=${options.Key}`);

  if (acl) options['ACL'] = acl;
  return await S3.putObject(options).promise();
}

export const removeFileFromS3 = async (bucket, key) => {
  const options = {
    Bucket: bucket,
    Key: key
  }

  return await S3.deleteObject(options, function (error, result) {
    if (error)
      logger.log(level.error, `S3 Delete Object : Error=${beautify(error)}`);
    else
      logger.log(level.info, `S3 Delete Object : Result=${beautify(result)}`);
  })
}

// export const getSignedUrl = async (bucket, key) => {
//   return await S3.getSignedUrlPromise('getObject', {
//     Bucket: bucket,
//     Key: key,
//     Expires: 60 * 60 * 24 * 7   // 90 days
//   });
// }

export const getSignedUrl = async (bucket, key) => {
  return process.env.CloudFrontURL + '/' + key
  // return signer.getSignedUrl({
  //   url: cfObjectUrl,
  //   expires: 60 * 60 * 24 * 7
  // });
};

export const signURL = async (url) => {
  if (url) {
    const newURL = await getSignedUrl(process.env.Aws_Bucket_Name, url);
    return newURL;
  } else {
    return url;
  }
}