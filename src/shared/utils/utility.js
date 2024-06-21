import JWTAuth from "./../services/jwt_auth/jwt_auth.service.js";
import { constants as APP_CONST, constants } from "./../constant/application.const.js";
import { logger, level } from "./../../config/logger.js";
import crypto from "crypto";
import shortid from "shortid";
import pkg from "lodash";
import mongoose from "mongoose";
import nodemailer from "nodemailer";
import { VerifyEmailHtml, ForgotPasswordHtml, TrialCodeEmailHtml ,LoginVerifyEmailHtml } from "./templates.js";
import messages from "../constant/messages.const.js";
import httpStatus from "http-status";
const { _ } = pkg;

const algorithm = "aes-256-cbc";
const enc_key = "3zTvzr3p67VC61jmV54rIYu1545x4TlY";

// ================================================
// To generate new IV
// ================================================
// const initiate_vector = crypto.randomBytes(16);
// IV = initiate_vector.toString('hex')

const IV = "366b6d5cae00e952bfe70e9260b93c0e"; // one kind of decryption key in a hex format (not utf8(string))

export const encrypt = (data) => {
  if (data) {
    try {
      var cipher = crypto.createCipheriv(
        algorithm,
        Buffer.from(enc_key, "utf8"),
        Buffer.from(IV, "hex")
      );
      const encrypted = Buffer.concat([
        cipher.update(Buffer.from(data, "utf8")),
        cipher.final(),
      ]);
      return encrypted.toString("hex");
    } catch (error) {
      logger.log(level.error, `encrypt error: ${error}`);
      return data;
    }
  }
  return data;
};

export const decrypt = (hash) => {
  if (hash) {
    try {
      const decipher = crypto.createDecipheriv(
        algorithm,
        enc_key,
        Buffer.from(IV, "hex")
      );
      const decrypted = Buffer.concat([
        decipher.update(Buffer.from(hash, "hex")),
        decipher.final(),
      ]);
      return decrypted.toString();
    } catch (error) {
      logger.log(level.error, `decrypt error: ${error}`);
      return hash;
    }
  }
  return hash;
};

export const sendStatus = (res, statusCode) => {
  res.status(statusCode);
};

export const sendResponse = (res, statusCode, data) => {
  res.status(statusCode).send(data);
};

export const sendJSONResponse = (res, statusCode, data) => {
  return res.status(statusCode).json(data);
};

export const redirectRequest = (res, url) => {
  res.status(301).redirect(getValidUrl(url));
};

export const getValidUrl = (url = "") => {
  const pattern = /^((http|https|ftp):\/\/)/;

  if (!pattern.test(url)) {
    url = "http://" + url;
  }

  return url;
};

export const createSuccessResponseJSON = (message, data = null, count = null) => {
  var json = { success: true, message, data: data };
  if (count != null) {
    json['count'] = count;
  }
  return json;
};
export const createSuccessResponseJSONTotalCount = (message, data = null, totalcount = null, count = null) => {
  var json = { success: true, message, data: data };
  if (count != null && totalcount != null) {
    json['count'] = count;
    json['totalcount'] = totalcount;
  }
  return json;
};

export const createSuccessResponseJSONDiff = (message, data = null, count = null) => {
  var json = { success: true, message, payload: data };
  if (count != null) {
    json['count'] = count;
  }
  return json;
};

export const createErrorResponseJSON = (message, error = null) => {
  return { success: false, message, error: error };
};

export const okResponse = (res, message, data = null, count = null) => {
  return sendJSONResponse(res, httpStatus.OK, createSuccessResponseJSON(message, data, count))
}
export const okResponseTotalCount = (res, message, data = null, totalcount = null, count = null) => {
  return sendJSONResponse(res, httpStatus.OK, createSuccessResponseJSONTotalCount(message, data, totalcount, count))
}

export const okResponseDiff = (res, message, data = null, count = null) => {
  return sendJSONResponse(res, httpStatus.OK, createSuccessResponseJSONDiff(message, data, count))
};

export const internalServerError = (res, error) => {
  return sendJSONResponse(res, httpStatus.INTERNAL_SERVER_ERROR, createErrorResponseJSON(messages.internal_server_error, error));
}

export const unauthorizedError = (res, message = messages.unauthorized, error = httpStatus["401_MESSAGE"], code = httpStatus.UNAUTHORIZED) => {
  return sendJSONResponse(res, code, createErrorResponseJSON(message, error))
}

export const badRequestError = (res, message = messages.bad_request, error = httpStatus["400_MESSAGE"], code = httpStatus.BAD_REQUEST) => {
  return sendJSONResponse(res, code, createErrorResponseJSON(message, error))
}
export const paramMissingError = (res, message = messages.invalid_input, error = httpStatus["417_MESSAGE"], code = httpStatus.EXPECTATION_FAILED) => {
  return sendJSONResponse(res, code, createErrorResponseJSON(message, error))
}

export const parseAuthToken = async ({ request, connection }) => {
  const AUTHORIZATION_HEADER_NAME = "authorization";
  let authorization;
  if (connection) {
    authorization = connection.context[AUTHORIZATION_HEADER_NAME];
  } else {
    authorization = request.headers[AUTHORIZATION_HEADER_NAME];
  }
  if (authorization) {
    const tokenSplitBy = " ";
    let token = authorization.split(tokenSplitBy);
    let length = token.length;
    const tokenLength = 2;
    if (length == tokenLength) {
      let accessToken = token[1];
      try {
        const auth = new JWTAuth();
        let decoded = await auth.verifyToken(accessToken);
        logger.log(
          level.silly,
          `utility parseAuthToken decoded=${JSON.stringify(decoded)}`
        );
        return decoded;
      } catch (err) {
        // logger.log(level.error, `utility parseAuthToken err=${err}`);
        return null;
      }
    }
  }
  return null;
};

export const parseAdminAuthToken = async ({ request, connection }) => {
  // logger.log(level.debug, `utlity parseAdminAuthToken`);
  const AUTHORIZATION_HEADER_NAME = "authorization";
  let authorization;
  if (connection) {
    authorization = connection.context[AUTHORIZATION_HEADER_NAME];
  } else {
    authorization = request.headers[AUTHORIZATION_HEADER_NAME];
  }
  if (authorization) {
    const tokenSplitBy = " ";
    let token = authorization.split(tokenSplitBy);
    let length = token.length;
    const tokenLength = 2;
    if (length == tokenLength) {
      let accessToken = token[1];
      try {
        const auth = new JWTAuth();
        let decoded = await auth.verifyAdminToken(accessToken);
        logger.log(
          level.silly,
          `utlity parseAuthToken decoded=${JSON.stringify(decoded)}`
        );
        return decoded;
      } catch (e) {
        // logger.log(level.error, `utlity parseAdminAuthToken ${e}`);
        return null;
      }
    }
  }
  return null;
};
export const wait = async (seconds) => {
  return new Promise((resolve) => {
    setTimeout(resolve, seconds * 1000);
  });
};

export const roundUpArrayNumber = (array, target) => {
  var off =
    target -
    _.reduce(
      array,
      function (acc, x) {
        return acc + Math.round(x);
      },
      0
    );
  return _.chain(array)
    .sortBy(function (x) {
      return Math.round(x) - x;
    })
    .map(function (x, i) {
      return Math.round(x) + (off > i) - (i >= array.length + off);
    })
    .value();
};

export const encodeBase64 = (encode) => {
  return Buffer.from(encode).toString("base64");
};

export const decodeBase64 = (decode) => {
  return Buffer.from(decode, "base64").toString("ascii");
};

export const generate = () => {
  return shortid.generate();
};

export const getDistanceFromLatLon = (lat1, lon1, lat2, lon2, unit) => {
  const RadiusInKM = 6371; // Radius of the earth in km
  const RadiusInMI = 3958.8; // Radius of the earth in mi

  const dLat = deg2rad(lat2 - lat1); // deg2rad below
  const dLon = deg2rad(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(deg2rad(lat1)) *
    Math.cos(deg2rad(lat2)) *
    Math.sin(dLon / 2) *
    Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  let d;
  if (unit == "km") {
    d = RadiusInKM * c; // Distance in km
  } else {
    d = RadiusInMI * c; // Distance in mi
  }
  return d;
};

export const deg2rad = (deg) => {
  return deg * (Math.PI / 180);
};

const algorithm1 = "aes256"; // or any other algorithm supported by OpenSSL
const key1 = "password";

export const decryptURL = (text) => {
  const decipher = crypto.createDecipher(algorithm1, key1);
  const decrypted =
    decipher.update(text, "hex", "utf8") + decipher.final("utf8");
  return decrypted;
};

export const trimAndLowercase = (text) => {
  return text ? text.toLowerCase().trim() : text;
};

export const beautify = (jsonObject) => {
  // return JSON.stringify(jsonObject, null, 2)
  return JSON.stringify(jsonObject);
};

export const replace_Id = (json) => {
  if (Array.isArray(json)) {
    json = json.map((item) => {
      return replace_Id(item);
    });
    return json;
  } else if (typeof json == "object") {
    for (let key in json) {
      if (key in json) {
        if (key == "_id") json["id"] = replace_Id(json[key]);
        else json[key] = replace_Id(json[key]);
      }
    }
    return json;
  } else {
    return json;
  }
};

export const toObjectId = (id) => {
  return mongoose.Types.ObjectId(id);
};

export const SendEmail = (email, email_type, OTP = null, NAME = null) => {
  return new Promise(async (resolve, reject) => {
    var transporter = nodemailer.createTransport({
      transport: "SMTP",
      host: "smtp.gmail.com",
      port: 587,
      auth: {
        user: process.env.FROM_MAIL_ID,
        pass: process.env.FROM_MAIL_PWD,
      },
      secure: false,
      tls: { rejectUnauthorized: false },
      debug: true,
    });

    if (email_type == "verification") {
      VerifyEmailHtml(OTP, NAME, process.env.HOST_URL).then((data) => {
        var mailOptions = {
          from: process.env.SEND_EMAIL_FROM_TEXT,
          to: email,
          subject: "Please Verify your account.",
          html: data,
          attachments: [
            {
              filename: "Wellheal_Logo.png",
              path: "src/public/Wellheal_Logo.png",
              cid: "logo"
            },
          ],
        };

        const mail = transporter.sendMail(mailOptions);
        return resolve(mail);
      },
        (error) => {
          reject(error);
        }
      );
    } else if (email_type == 'trialCoupon') {
      TrialCodeEmailHtml(OTP, NAME).then((data) => {
        var mailOptions = {
          from: process.env.SEND_EMAIL_FROM_TEXT,
          to: email,
          subject: "Here is your Trial Coupon Code.",
          html: data,
          attachments: [
            {
              filename: "Wellheal_Logo.png",
              path: "src/public/Wellheal_Logo.png",
              cid: "logo"
            },
          ],
        };

        const mail = transporter.sendMail(mailOptions);
        return resolve(mail);
      },
        (error) => {
          reject(error);
        }
      );
    } else if (email_type == 'user_report') {
      var mailOptions = {
        from: process.env.SEND_EMAIL_FROM_TEXT,
        to: email,
        subject: "Here is your Health Report.",
        attachments: [
          {
            filename: "Health_Report.pdf",
            path: OTP,   // Here OTP variable contain is Pdf Path
            cid: "Health Report"
          },
        ],
      };

      const mail = transporter.sendMail(mailOptions);
      return resolve(mail);
    }
    else if(email_type == "login_verification"){
      LoginVerifyEmailHtml(OTP, NAME, process.env.HOST_URL).then((data) => {
        var mailOptions = {
          from: process.env.SEND_EMAIL_FROM_TEXT,
          to: email,
          subject: "Please Verify your account.",
          html: data,
          attachments: [
            {
              filename: "Wellheal_Logo.png",
              path: "src/public/Wellheal_Logo.png",
              cid: "logo"
            },
          ],
        };

        const mail = transporter.sendMail(mailOptions);
        return resolve(mail);
      },
        (error) => {
          reject(error);
        }
      );
    } 
    else {
      var date = new Date();
      var milliseconds = date.getTime();
      const random_string = await makeid(30);
      var URL = `${APP_CONST.API_URL}/auth/${encrypt(email)}/password/${milliseconds}/${random_string}/${Buffer.from(constants.VERIFICATION_TOKEN, 'binary').toString('base64')}`
      ForgotPasswordHtml(URL, NAME).then((data) => {
        var mailOptions = {
          from: process.env.SEND_EMAIL_FROM_TEXT,
          to: email,
          subject: "Your reset password link.",
          html: data,
          attachments: [
            {
              filename: "Wellheal_Logo.png",
              path: "src/public/Wellheal_Logo.png",
              cid: "logo"
            },
          ],
        };

        const mail = transporter.sendMail(mailOptions);
        if (!mail) random_string = null;
        return resolve(random_string);
      },
        (error) => {
          reject(error);
        }
      );
    }
  });
};

export const makeid = async (length) => {
  var result = "";
  var characters =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  var charactersLength = characters.length;
  for (var i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength));
  }
  return result;
}

export const makeNumericId = async (length) => {
  var result = "";
  var characters =
    "1234567890";
  var charactersLength = characters.length;
  for (var i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength));
  }
  return result;
}

export const getPaginationOptions = (option) => {
  /* if (option && option.sort) {
    for (const field in option.sort) {
      option.sort[field] = Number(option.sort[field])
    }
  } */
  const opArgs = [];
  
  if (option && option.sort) {
    const sort = {};
    for (const field in option.sort) {
      sort[field] = Number(option.sort[field]);
    }
    opArgs.push({ $sort: sort });
  }
  
  option && option.offset ? opArgs.push({ $skip: Number(option.offset) }) : null;
  option && option.limit ? opArgs.push({ $limit: Number(option.limit) }) : null;
  //option && option.sort ? opArgs.push({ $sort: option.sort }) : null;
  return opArgs
}

export const generateRandomString = () => {
  let result = '';
  let characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let charactersLength = characters.length;
  for (let i = 0; i < parseInt(Math.random() * (30 - 20) + 22); i++) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength));
  }
  return `${result}${Date.now()}`;
}

export const insertIf = (condition, value, elseValue = null) => {
  return condition ? Object.values({ x: value }) : Object.values(elseValue ? { x: elseValue } : {})
}

export const loop = async (arr = [], callback = async function () { }) => {
  for (let i = 0; i < arr.length; i++) {
    await callback(arr[i]);
  }
}

export const parseSearchOptions = async (option) => {
  var filter = {};
  var ANDArray = [];
  var ORArray = [];
  if ('search' in option) {
    if ('searchBy' in option && option.searchBy == 'AND') {
      ANDArray = await calculateFilterArrayFromSearch(option.search, ANDArray);
    } else {
      ORArray = await calculateFilterArrayFromSearch(option.search, ORArray);
    }
  }
  if (ANDArray.length > 0) {
    filter = { $and: [...ANDArray] }
  } else if (ORArray.length > 0) {
    filter = { $or: [...ORArray] }
  }
  return filter;
}

async function calculateFilterArrayFromSearch(search, array = []) {
  Object.keys(search).forEach(key => {
    if (key in search) {
      let value = Object.values(search[key])[0];
      const operator = Object.keys(search[key])[0];
      switch (operator) {
        case 'like':
          array.push({ [key]: { $regex: new RegExp(value), $options: 'i' } })
          break;
        case 'eq':
          array.push({ [key]: value })
          break;
      }
    }
  });
  return array;
}