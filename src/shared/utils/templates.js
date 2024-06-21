import { level } from "../../config/logger.js";
import logger from "../../config/winston.js";
import { constants as APP_CONST } from "./../constant/application.const.js";
import path from "path";
import ejs from "ejs";
const __dirname = path.resolve();

export const VerifyEmailHtml = (OTP, NAME, HOST) => {
    // const URL = `${APP_CONST.API_URL}/auth/users/verify/${email}`;
    return new Promise((resolve, reject) => {
        ejs.renderFile(path.join(__dirname, "src", "views", "/emailVarificationTemplate.ejs"), { OTP, NAME, HOST }, (err, data) => {
            if (err) {
                logger.log(level.error, `Email verify Template error : ${JSON.stringify(err)}`)
                reject(err)
            } else {
                resolve(data)
            }
        });
    });
};

export const LoginVerifyEmailHtml = (OTP, NAME, HOST) => {
    return new Promise((resolve, reject) => {
        ejs.renderFile(path.join(__dirname, "src", "views", "/emailLoginVarificationTemplate.ejs"), { OTP, NAME, HOST }, (err, data) => {
            if (err) {
                logger.log(level.error, `Email verify Template error : ${JSON.stringify(err)}`)
                reject(err)
            } else {
                resolve(data)
            }
        });
    });
};

export const TrialCodeEmailHtml = (OTP, NAME) => {
    return new Promise((resolve, reject) => {
        ejs.renderFile(path.join(__dirname, "src", "views", "/trialCodeTemplate.ejs"), { OTP, NAME, APP_STORE_APP_LINK: process.env.APP_STORE_APP_LINK }, (err, data) => {
            if (err) {
                logger.log(level.error, `Trial Code Email Template error : ${JSON.stringify(err)}`)
                reject(err)
            } else {
                resolve(data)
            }
        });
    });
};

export const ForgotPasswordHtml = (url, NAME) => {
    return new Promise((resolve, reject) => {
        ejs.renderFile(path.join(__dirname, "src", "views", "/forgotPasswordEmailTemplate.ejs"), { URL: url, NAME }, (err, data) => {
            if (err) {
                logger.log(level.error, `forgot password Template error : ${JSON.stringify(err)}`)
                reject(err)
            } else {
                resolve(data)
            }
        });
    });
};

export const UserReportHtml = (HOST, OBJ) => {
    return new Promise((resolve, reject) => {
        ejs.renderFile(path.join(__dirname, "src", "views", "/report.ejs"), { HOST, OBJ }, (err, data) => {
            if (err) {
                logger.log(level.error, `user report Template error : ${JSON.stringify(err)}`)
                reject(err)
            } else {
                resolve(data)
            }
        });
    });
};
