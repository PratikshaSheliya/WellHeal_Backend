import HTTPStatus from 'http-status';
import { logger, level } from '../config/logger.js';
import JWTAuth from '../shared/services/jwt_auth/jwt_auth.service.js';
import pkg from 'lodash';
import {
  SendEmail,
  decrypt,
  encrypt,
  beautify,
  internalServerError,
  paramMissingError,
  badRequestError,
  okResponse,
  generateRandomString,
  makeid,
  makeNumericId,
  toObjectId,
} from '../shared/utils/utility.js';
import { REGEX } from '../shared/constant/application.const.js';
import User from '../models/user.model.js';
import Payment from '../models/payment.model.js';
import {
  constants as APP_CONST,
  UPLOAD_PATH,
} from '../shared/constant/application.const.js';
import messages from '../shared/constant/messages.const.js';
import moment from 'moment';
import UserToken from '../models/user_token.model.js';
import {
  returnOnExist,
  returnOnNotExist,
} from '../shared/services/database/query.service.js';
import {
  COUPON_FOR_WHO,
  COUPON_TYPE,
  IMAGE_EXTENSIONS,
  TYPES,
  USER_PRO_STATUS,
  USER_ROLE,
} from '../shared/constant/types.const.js';
import Path from 'path';
import {
  getSignedUrl,
  removeFileFromS3,
  uploadFileToS3,
} from '../shared/services/file-upload/aws-s3.service.js';
import Coupon from '../models/coupon.model.js';
import Stripe from "stripe";
import TrialUsers from "../models/trialUser.model.js";

const { _ } = pkg;
const auth = new JWTAuth();
const asset_url = `${APP_CONST.ASSET_URL}`;

export const login = async (req, res) => {
  try {
    let data = req.body;

    logger.log(level.info, `Login Data: ${beautify(data)}`);
    if (!data.device_id || !data.device_token || !data.device_type) {
      logger.log(level.info, 'login device info missing error');
      return paramMissingError(
        res,
        messages.missing_key.replace(
          '{dynamic}',
          'device_id Or device_token Or device_type'
        ),
        null
      );
    }
    if (data.login_type == TYPES.LOGIN_TYPE_NORMAL) {
      /* Normal login */
      if (!data.phone_number) {
        if (!data.email) {
          return paramMissingError(
            res,
            messages.missing_key.replace('{dynamic}', 'Email')
          );
        }
        // if (!data.password) {
        //   return paramMissingError(
        //     res,
        //     messages.missing_key.replace('{dynamic}', 'Password')
        //   );
        // }
      }

      const filter = {};
      if (data.phone_number) {
        filter['phone_number'] = data.phone_number;
      } else if (data.email) {
        filter['email'] = data.email;
        filter['password'] = data.password;
      } else {
        return paramMissingError(
          res,
          messages.missing_key.replace('{dynamic}', 'Email | Phone Number')
        );
      }
      let userDoc = await userExist(filter);
      // TODO:


      if (userDoc.length > 0) {
        // userDoc[0] = await User.update(
        //   { _id: userDoc[0]._id },
        //   {
        //     is_doctor_consulted: data?.is_doctor_consulted,
        //     doctor_suggestion: data?.doctor_suggestion,
        //   }
        // );
        let paymentDoc = await paymentExists(userDoc[0]._id);
        generateToken(res, data.email , userDoc[0], paymentDoc); // data.email|| data.password
        await addOrUpdateDeviceTokens(userDoc[0]._id, data);
      } else {
        return badRequestError(
          res,
            data.phone_number ? messages.user_missing : messages.email_password_not_match,
          null,
          HTTPStatus.NOT_FOUND
        );
      }
    } 
    else if(data.login_type == TYPES.LOGIN_TYPE_GOOGLE || data.login_type == TYPES.LOGIN_TYPE_FACEBOOK || data.login_type == TYPES.LOGIN_TYPE_FACEBOOK || data.login_type == TYPES.LOGIN_TYPE_APPLE ) {
      /* Social login */
      const filter = { social_id: data.social_id };
      if (data.email) filter['email'] = data.email;
      let userDoc = await userExist(filter);
      if (userDoc.length > 0) {
        // userDoc[0] = await User.update(
        //   { _id: userDoc[0]._id },
        //   {
        //     is_doctor_consulted: data?.is_doctor_consulted,
        //     doctor_suggestion: data?.doctor_suggestion,
        //   }
        // );
        let paymentDoc = await paymentExists(userDoc[0]._id);
        generateToken(res, data['email'] || null, userDoc[0], paymentDoc);
        await addOrUpdateDeviceTokens(userDoc[0]._id, data);
      } else {
        // const isExist = await User.isExist({ email: data.email, login_type: { $ne: TYPES.LOGIN_TYPE_NORMAL } });
        // if (isExist) {
        //   return badRequestError(res, messages.invalid_key.replace("{dynamic}", "Invalid Social Id For This Email"))
        // }

        if (data?.email) {
          const isNormalEmailExist = await User.isExist({
            email: data.email,
            login_type: TYPES.LOGIN_TYPE_NORMAL,
          });
          if (isNormalEmailExist) {
            return badRequestError(res, messages.email_is_already_in_use);
          }
        }
        // const isExist = await returnOnExist(User, { email: data.email }, res, "Email", messages.already_exist.replace("{dynamic}", "Email"));
        // if (isExist) return;

        let newUser = createNewUser({
          is_verified: true,
          name: data.name || '',
          login_type: data.login_type,
          email: data?.email || '',
          social_id: data.social_id,
          password: encrypt(`${data?.email || ''}_${data.social_id}`),
          role: data?.role || USER_ROLE.PATIENT,
          is_doctor_consulted: data?.is_doctor_consulted,
          doctor_suggestion: data?.doctor_suggestion,
          userTrial: false,
        });
        userDoc = await User.add(newUser);
        let paymentDoc = await paymentExists(userDoc._id);
        let freeTrialUserDoc={};
        generateToken(res, userDoc?.email | '', userDoc, paymentDoc,freeTrialUserDoc);
        await addOrUpdateDeviceTokens(userDoc._id, data);
      }
    }
    else{
      return badRequestError(res, messages.invalid_key.replace("{dynamic}", "Invalid Login Type Please check your login type"))
    }
  } catch (error) {
    logger.log(
      level.error,
      `Login : Internal server error : ${beautify(error.message)}`
    );
    return internalServerError(res, error.message);
  }
};

export const logout = async (req, res) => {
  try {
    let data = req.body;
    logger.log(level.info, `Login Data: ${beautify(data)}`);
    if (!data.device_id || !data.user_id) {
      logger.log(level.info, 'login device info missing error');
      return paramMissingError(
        res,
        messages.missing_key.replace(
          '{dynamic}',
          'device_id Or device_token Or device_type'
        ),
        null
      );
    }
    const deletedCondition = {
      $or: [{ is_loggedOut: false }, { is_loggedOut: { $exists: false } }],
    };
    const filter = {
      user_id: data.user_id,
      device_id: data.device_id,
      ...deletedCondition,
    };
    const user = await UserToken.update(filter, {
      is_loggedOut: true,
      loggedOut_at: new Date().toISOString(),
    });
    return okResponse(
      res,
      messages.updated.replace('{dynamic}', 'log out'),
      user
    );
  } catch (error) {
    logger.log(
      level.error,
      `Login : Internal server error : ${beautify(error.message)}`
    );
    return internalServerError(res, error.message);
  }
};

export const signUp = async (req, res) => {
  try {
        const { body, file } = req;
        let data = body;
        let newUser = {
          name: data.name,
          email: data.email,
          phone_number: data.phone_number,
          //password: data.password,
          address: data.address,
          city: data.city,
          state: data.state,
          country: data.country,
          countryCode: data.countryCode,
          zipcode: data.zipcode,
          dob: data.dob,
          gender: data.gender,
          role: data?.role || USER_ROLE.PATIENT,
          is_doctor_consulted: data?.is_doctor_consulted,
          doctor_suggestion: data?.doctor_suggestion || [],
          is_verified: data.phone_number ? true : false,
          is_deleted: false,
          userTrial: false,
        };
        logger.log(level.info, `User Registeration Body : ${beautify(data)}`);

        if (!data.device_id || !data.device_token || !data.device_type || !data.login_type) {
            logger.log(level.info, 'signup device info missing error');
            return paramMissingError(
              res,
              messages.missing_key.replace(
                '{dynamic}',
                'device_id Or device_token Or device_type Or login_type'
              ),
              null
            );
        }
        if (data.login_type == TYPES.LOGIN_TYPE_NORMAL) {
          if (!data.phone_number) {
            if (!data.email) {
              logger.log(level.error, 'User Registeration:  no email error');
              return paramMissingError(
                res,
                messages.missing_key.replace('{dynamic}', 'Email')
              );
            } 
            if (!data.email & !data.phone_number) {
              logger.log(
                level.error,
                'User Registeration:  no email or phone number error'
              );
              return paramMissingError(
                res,
                messages.missing_key.replace('{dynamic}', 'Email | Phone Number')
              );
            }
          } else {
            if (!data.countryCode) {
              logger.log(level.error, 'User Registeration:  no Countrycode error');
              return paramMissingError(
                res,
                messages.missing_key.replace('{dynamic}', 'country code')
              );
            }
          }
      
          if (file) {
            const filePath = Path.parse(file.originalname);
            if (!Object.values(IMAGE_EXTENSIONS).includes(filePath.ext)) {
              logger.log(
                level.info,
                'User Registeration: invalid file selection error'
              );
              return badRequestError(res, messages.invalid_file_selected);
            }
          }
      
          let filter = {};
          data.email ? (filter['email'] = data.email) : null;
          data.phone_number ? (filter['phone_number'] = data.phone_number) : null;
          data.email && data.phone_number ? (filter = {$or: [{ email: data.email }, { phone_number: data.phone_number }],}): null;
          filter = {...filter, $or: [{ is_deleted: false }, { is_deleted: { $exists: false } }],};
          logger.log(level.info, `singup UserFilter: ${beautify(filter)}`);
    
          /* ====================Code For Login if user is Already Exists====================*/
          let userDoc = await userExist(filter);
          if (userDoc.length > 0) {
              if(userDoc[0].login_type === Number(data.login_type)){

                let userDocs =await User.update({ _id: userDoc[0]._id }, { is_signup: false });
                let paymentDoc = await paymentExists(userDoc[0]._id);
        
                if (userDoc[0].email) {
                  const OTP = await makeNumericId(6);
                  logger.log(level.info, `singup generatedOTP=${OTP}`);
                  await User.update({ _id: userDoc[0]._id }, { confirmation_otp: OTP });
                  await SendEmail(
                    userDoc[0].email,
                    'login_verification',
                    OTP,
                    userDoc[0]?.name || 'There'
                  );
                }
                delete userDoc[0]['confirmation_otp'];
                generateToken(res, data.email , userDocs, paymentDoc); // data.email|| data.password
                await addOrUpdateDeviceTokens(userDoc[0]._id, data);
              }
              else{
                return badRequestError(res, messages.email_is_already_in_use_with_other_social_account);
              }  
            }else{
              let freeTrialUserDoc={};
              User.add(newUser,freeTrialUserDoc).then(
              async (resp) => {
                if (file) {
                  const filePath = Path.parse(file.originalname);
                  const fileName = generateRandomString();
                  const s3Location = `${UPLOAD_PATH.Profile}${resp._id}/${fileName}${filePath.ext}`;
                  uploadFileAndUpdateProfileURL(s3Location, file, { _id: resp._id });
                  resp['profile_image'] = await getSignedUrl(
                    process.env.Aws_Bucket_Name,
                    s3Location
                  );
                }
                addOrUpdateDeviceTokens(resp._id, data);
                if (resp.email) {
                  const OTP = await makeNumericId(6);
                  logger.log(level.info, `singup generatedOTP=${OTP}`);
                  await User.update({ _id: resp._id }, { confirmation_otp: OTP });
                  await SendEmail(
                    resp.email,
                    'verification',
                    OTP,
                    resp?.name || 'There'
                  );
                }
                delete resp['confirmation_otp'];
                generateToken(res, data.email || data.phone_number, resp);
              },
              (error) => {
                logger.log(
                  level.error,
                  `User Registeration Error : ${beautify(error.message)}`
                );
                return internalServerError(res, error);
              }
            );
            }          
        }
        /* Social signup & login */
        else if(data.login_type == TYPES.LOGIN_TYPE_GOOGLE || data.login_type == TYPES.LOGIN_TYPE_FACEBOOK || data.login_type == TYPES.LOGIN_TYPE_FACEBOOK || data.login_type == TYPES.LOGIN_TYPE_APPLE ) {
          
          if (!data.social_id) {
            logger.log(level.info, 'signup device info missing error');
            return paramMissingError(res,messages.missing_key.replace('{dynamic}','social_id'),null);
          }
          
          const filter = { social_id: data.social_id };
          if (data.email) filter['email'] = data.email;
          //Social Login Code
          let userDoc = await userExist(filter);
            if (userDoc.length > 0) {
                if(userDoc[0].login_type === Number(data.login_type)){
                  let userDocs =await User.update({ _id: userDoc[0]._id }, { is_signup: false });
                  let paymentDoc = await paymentExists(userDoc[0]._id);
                  generateToken(res, data['email'] || null, userDocs, paymentDoc);
                  await addOrUpdateDeviceTokens(userDoc[0]._id, data);
                }
                else{
                  return badRequestError(res, messages.email_is_already_in_use_with_other_social_account);
                }
            } else {
              if (data?.email) {
                const isNormalEmailExist = await User.isExist({
                  email: data.email,
                  login_type: TYPES.LOGIN_TYPE_NORMAL,
                });
                if (isNormalEmailExist) {
                  return badRequestError(res, messages.email_is_already_in_use);
                }
              }
            
              let newUser = createNewUser({
                is_verified: true,
                name: data.name || '',
                login_type: data.login_type,
                email: data?.email || '',
                social_id: data.social_id,
                password: encrypt(`${data?.email || ''}_${data.social_id}`),
                role: data?.role || USER_ROLE.PATIENT,
                is_doctor_consulted: data?.is_doctor_consulted,
                doctor_suggestion: data?.doctor_suggestion,
                userTrial: false,
              });
              userDoc = await User.add(newUser);
              let paymentDoc = await paymentExists(userDoc._id);
              let freeTrialUserDoc={};
              generateToken(res, userDoc?.email | '', userDoc, paymentDoc,freeTrialUserDoc);
              await addOrUpdateDeviceTokens(userDoc._id, data);
            }    
        }
        else{
          return badRequestError(res, messages.invalid_key.replace("{dynamic}", "Invalid Login Type Please check your login type"))
        }
    } catch (error) {
      logger.log(
        level.error,
        `User Registeration Error Error=${beautify(error.message)}`
      );
      return internalServerError(res, error);
    }
};

export const verifyOTP = async (req, res) => {
  try {
    const { email, otp } = req.body;
    logger.log(level.info, `VerifyOTP otp=${otp}`);

    if (!otp) {
      logger.log(level.error, 'VerifyOTP:  no OTP found error');
      return paramMissingError(
        res,
        messages.missing_key.replace('{dynamic}', 'One Time Password')
      );
    }
    const filter = {
      email: email,
      login_type: TYPES.LOGIN_TYPE_NORMAL,
      confirmation_otp: otp,
    };
    const [user] = await User.get({
      email: email,
      login_type: TYPES.LOGIN_TYPE_NORMAL,
    });
    const [user_with_otp] = await User.get(filter);
    logger.log(
      level.info,
      `verify OTP User: ${beautify(user)} user_with_otp: ${beautify(
        user_with_otp
      )}`
    );
    const updated = await User.update(filter, {
      is_verified: true,
      confirmation_otp: null,
    });
    if (updated) {
      return okResponse(res, messages.user_verified_success);
    } else {
      return badRequestError(res, messages.otp_expired);
    }
  } catch (error) {
    logger.log(level.error, `VerifyOTP Error=${error.message}`);
    return internalServerError(res, error);
  }
};

export const resendOTP = async (req, res) => {
  try {
    const { email } = req.body;
    logger.log(level.info, `VerifyOTP email=${email}`);

    const filter = { email, login_type: TYPES.LOGIN_TYPE_NORMAL };

    const notExist = await returnOnNotExist(
      User,
      filter,
      res,
      'User',
      messages.not_exist.replace('{dynamic}', 'User')
    );
    if (notExist) return;

    const [user] = await User.get(filter);
    const OTP = await makeNumericId(6);
    await User.update(filter, { confirmation_otp: OTP });
    await SendEmail(email, 'verification', OTP, user?.name || 'There');

    return okResponse(res, messages.email_sent);
  } catch (error) {
    logger.log(level.error, `resendOTP Error=${error.message}`);
    return internalServerError(res, error);
  }
};

export const updateUserDetail = async (req, res, next) => {
  try {
    const { body, file } = req;
    const {
      name = null,
      address = null,
      city = null,
      state = null,
      country = null,
      countryCode = null,
      zipcode = null,
      dob = null,
      gender = null,
    } = body;

    logger.log(level.info, `updateUserDetail body=${beautify(body)}`);

    const payload = {};
    if (name) payload['name'] = name;
    if (address) payload['address'] = address;
    if (city) payload['city'] = city;
    if (state) payload['state'] = state;
    if (country) payload['country'] = country;
    if (countryCode) payload['countryCode'] = countryCode;
    if (zipcode) payload['zipcode'] = zipcode;
    if (dob) payload['dob'] = dob;
    if (gender) payload['gender'] = gender;

    const filter = { _id: req['currentUserId'] };

    const user = await User.update(filter, payload);
    let s3Location;
    if (file) {
      const filePath = Path.parse(file.originalname);
      const fileName = generateRandomString();
      s3Location = `${UPLOAD_PATH.Profile}${req['currentUserId']}/${fileName}${filePath.ext}`;

      if (!Object.values(IMAGE_EXTENSIONS).includes(filePath.ext)) {
        logger.log(
          level.info,
          'updateUserDetail: invalid file selection error'
        );
        return badRequestError(res, messages.invalid_file_selected);
      }

      const [user] = await User.get(filter);
      if (user && user.profile_image) {
        removeFileFromS3(process.env.Aws_Bucket_Name, user.profile_image);
      }
      uploadFileAndUpdateProfileURL(s3Location, file, filter);
    }

    if (s3Location) {
      // set this due to pervent old urlsigning
      user['profile_image'] = await getSignedUrl(
        process.env.Aws_Bucket_Name,
        s3Location
      );
    }

    return await okResponse(
      res,
      messages.updated.replace('{dynamic}', 'User'),
      user
    );
  } catch (error) {
    logger.log(
      level.error,
      `updateUserDetail Error: ${beautify(error.message)}`
    );
    return internalServerError(res, error);
  }
};

export const forgotPassword = async (req, res) => {
  try {
    let data = req.body;
    logger.log(level.info, `forgotPassword Body : ${beautify(data)}`);

    let userData = await userExist({ email: data.email });
    logger.log(
      level.info,
      `forgot userData: ${beautify(userData)} name: ${userData[0]?.name}`
    );

    if (userData.length > 0) {
      const mail = await SendEmail(
        data.email || userData.email,
        'forgot_password',
        null,
        userData[0]?.name || 'There'
      );
      if (mail) {
        const random_string = mail;
        var insertMailId = {
          random_string: random_string,
        };
        await User.update(
          { email: data.email || userData.email },
          insertMailId
        );
      }
      return okResponse(res, messages.email_sent, null);
    } else {
      return badRequestError(
        res,
        messages.user_missing,
        null,
        HTTPStatus.NOT_FOUND
      );
    }
  } catch (error) {
    logger.log(level.error, `forgotPassword Error=${beautify(error.message)}`);
    return internalServerError(res, error);
  }
};

export const phoneExists = async (req, res) => {
  try {
    var data = req.body;
    logger.log(level.info, `phoneExists Body : ${beautify(data)}`);

    var phone_valid = REGEX.phone_number;
    let phone = phone_valid.test(data.phone);

    var country_code = REGEX.country_code;
    let cc = country_code.test(data.country_code);

    if (!phone || !cc) {
      return badRequestError(
        res,
        messages.invalid_key.replace('{dynamic}', 'Phone Number')
      );
    }

    const filter = { phone_number: data.phone, countryCode: data.country_code, is_deleted: false };
    let [userDoc] = await User.get(filter);
    if (userDoc) {
      return okResponse(res, messages.phone_exists, true);
    } else {
      return okResponse(
        res,
        messages.not_exist.replace('{dynamic}', 'Phone Number'),
        false
      );
    }
  } catch (error) {
    logger.log(level.error, `phoneExists Error=${beautify(error.message)}`);
    return internalServerError(res, error);
  }
};

export const getUserByID = async (req, res) => {
  try {
    var query_params = req.query;
    logger.log(level.info, `getUserByID Body : ${beautify(query_params)}`);

    const deletedCondition = { $or: [{ is_deleted: false }, { is_deleted: { $exists: false } }] }
    const filter = { _id: query_params.id, ...deletedCondition };
    const notExist = await returnOnNotExist(User, filter, res, "User", messages.not_exist.replace("{dynamic}", "User"));
    if (notExist) return;

    let [userData] = await userExist({ _id: query_params.id });

    if (userData) {
        const user_id = userData._id;
        const  access_token= userData.access_token;
        
        let paymentDoc = await paymentExists(user_id);

        const projection = { startTrial: 1, endTrial: 1 };

        const [TrialUser] = await TrialUsers.get({user_id:user_id},projection);
        let freeTrialUserDoc={};

        if(TrialUser && Object.keys(TrialUser).length > 0){
          freeTrialUserDoc =TrialUser;
        }
        else{
          freeTrialUserDoc=freeTrialUserDoc;
        }
      return okResponse(res, messages.user_found,{access_token:access_token,userDoc:userData,paymentDoc:paymentDoc,freeTrialUserDoc:freeTrialUserDoc});
    //  return okResponse(res, messages.user_found, {userData:userData,paymentDoc:paymentDoc,freeTrialUserDoc:freeTrialUserDoc});
    } else {
      return okResponse(res, messages.user_missing, null);
    }
  } catch (error) {
    logger.log(level.error, `getUserByID Error=${beautify(error.message)}`);
    return internalServerError(res, error);
  }
};

export const resetPasswordCheckLink = async (req, res) => {
  try {
    const { email, mailid, time } = req.params;
    var isValid = await authUserForgotPasswordCheckEmail(email, mailid, time);
    if (isValid == true) {
      res.send({ code: 200 });
    } else {
      res.send({ code: 400 });
    }
  } catch (e) {
    res.send({ status: 400, error: e.message });
  }
};

export const updatePassword = async (req, res) => {
  try {
    const { email, password } = req.params;
    var updated = await User.update({ email: decrypt(email) }, { password });
    if (updated) {
      await User.update({ email: decrypt(email) }, { random_string: '' });
      res.send({ code: 200 });
    } else {
      res.send({ code: 400 });
    }
  } catch (e) {
    res.send({ status: 400, error: e.message });
  }
};

/* Pages Redirection */

export const resetPasswordPage = async (req, res) => {
  res.render('change_password.ejs', {
    asset_url,
    apiURL: APP_CONST.API_URL,
  });
};

export const resetPasswordLinkExpirePage = async (req, res) => {
  res.render('expired.ejs', { asset_url });
};

export const passwordUpdatedPage = async (req, res) => {
  res.render('change_pass_success.ejs', { asset_url });
};

export const passwordUpdateFailedPage = async (req, res) => {
  res.render('change_pass_failure.ejs', { asset_url });
};

/* Commonly used functions */

async function authUserForgotPasswordCheckEmail(
  email,
  random_string,
  timestamp
) {
  try {
    var emailId = await decrypt(email);
    let [email_with_string_exist] = await User.get({
      email: emailId,
      random_string: random_string,
    });
    logger.log(
      level.info,
      `user: ${emailId}, random_string: ${random_string}, email_with_string_exist: ${email_with_string_exist}`
    );
    let date = new Date(parseInt(timestamp));
    var now = new Date();

    var ms = moment(now, 'YYYY-MM-DD HH:mm:ss').diff(
      moment(date, 'YYYY-MM-DD HH:mm:ss')
    );
    var data = moment.duration(ms);
    if (email_with_string_exist && data._data.days < 1) {
      return true;
    } else {
      return false;
    }
  } catch (e) {
    logger.log(
      level.error,
      `Error in Check Mail: ${JSON.stringify(e.message)}`
    );
    return false;
  }
}

async function generateToken(
  res,
  email,
  userDoc = null,
  paymentDoc = null
) {
  //console.log('\n\n USER DOC :: ', userDoc);
  let doc = JSON.parse(JSON.stringify(userDoc));
  let payDoc = JSON.parse(JSON.stringify(paymentDoc));

  const accessToken = await auth.createToken(email, doc.user_id);
  delete doc?.password;

  await User.update({_id: doc.user_id}, {access_token: accessToken});

  if (doc && doc.trial_redeem_time) {
    doc = await updateUserPRODetails(doc);
  } else {
    // Trial not started yet
    doc[USER_PRO_STATUS.TRIAL] = false;
    doc[USER_PRO_STATUS.TRIAL_EXPIRED] = false;
  }
  delete doc['confirmation_otp'];
 
  const user_id = doc.user_id;
  const projection = { startTrial: 1, endTrial: 1 };
  const [TrialUser] = await TrialUsers.get({user_id:user_id},projection);

  let freeTrialUserDoc={};

    if(TrialUser && Object.keys(TrialUser).length > 0){
      freeTrialUserDoc =TrialUser;
    }
    else{
      freeTrialUserDoc=freeTrialUserDoc;
    }
  return okResponse(res, messages.login_success, {
    access_token: accessToken,
    userDoc: doc,
    paymentDoc: payDoc, 
    freeTrialUserDoc:freeTrialUserDoc
  });
}

async function updateUserPRODetails(userDoc) {
  const doc = JSON.parse(JSON.stringify(userDoc));
  const trialFilter = {
    user_id: doc.user_id,
    coupon_type: COUPON_TYPE.TRIAL_COUPON,
    coupon_for: COUPON_FOR_WHO.SINGLE_USER,
    is_deleted: false,
  };
  logger.log(
    level.info,
    `update User's pro details : ${beautify(doc)} CouponFilter: ${beautify(
      trialFilter
    )}`
  );
  const [coupon] = await Coupon.get(trialFilter);
  if (coupon) {
    let date = new Date(doc.trial_redeem_time);
    var now = new Date();

    var ms = moment(now, 'YYYY-MM-DD HH:mm:ss').diff(
      moment(date, 'YYYY-MM-DD HH:mm:ss')
    );
    var data = moment.duration(ms);
    logger.log(
      level.info,
      `Difference : ${data._data.days}, Expire (In Day): ${coupon.expire_time}`
    );
    if (data._data.days <= coupon.expire_time) {
      doc[USER_PRO_STATUS.TRIAL] = true;
      doc[USER_PRO_STATUS.TRIAL_EXPIRED] = false;
    } else {
      doc[USER_PRO_STATUS.TRIAL] = false;
      doc[USER_PRO_STATUS.TRIAL_EXPIRED] = true;
    }
  } else {
    // Coupon not generated yet
    doc[USER_PRO_STATUS.TRIAL] = false;
    doc[USER_PRO_STATUS.TRIAL_EXPIRED] = false;
  }
  return { ...doc };
}

export const checkForTrialEnd = async (req, res) => {
  try {
    let doc = await User.get({ _id: toObjectId(req['currentUserId']) });
    let userDoc = doc.length > 0 ? JSON.parse(JSON.stringify(doc[0])) : null;
    if (userDoc && userDoc.trial_redeem_time) {
      userDoc = await updateUserPRODetails(userDoc);
    } else {
      // Trial not started yet
      userDoc[USER_PRO_STATUS.TRIAL] = false;
      userDoc[USER_PRO_STATUS.TRIAL_EXPIRED] = false;
    }
    return okResponse(res, messages.trial_not_exceeded, { ...userDoc });
  } catch (error) {
    logger.log(
      level.error,
      `checkForTrialEnd Error=${beautify(error.message)}`
    );
    return internalServerError(res, error);
  }
};

function createNewUser(userData) {
  return {
    email: userData.email,
    name: userData.name,
    login_type: userData.login_type,
    status: 1,
    is_verified: userData.is_verified,
    social_id: userData.social_id,
    password: userData.password,
    access_token: userData.access_token,
    profile_image: userData.profile_image,
    role: userData.role,
    is_doctor_consulted: userData.is_doctor_consulted,
    doctor_suggestion: userData.doctor_suggestion || [],
    userTrial:userData.userTrial,
  };
}

async function userExist(filter) {
  let userDoc = await User.get({
    ...filter,
    $or: [{ is_deleted: false }, { is_deleted: { $exists: false } }],
  });
  return userDoc || [];
}

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

async function paymentExists(user_id) {
  let paymentDoc = await Payment.get({
    user_id: user_id,
    $or: [{is_deleted: false}, {is_deleted: {$exists: false}}],
  }, {}, {}, {path: "plan_type"});
  paymentDoc?.sort(function(a,b){
    return b.created_at - a.created_at;
  });
  let payload = {};
  if (paymentDoc.length > 0) {
    if(paymentDoc[0]?.is_schedule) {
      let price = {};
      let product;
      let productName;
      if (paymentDoc[0]?.priceId) {
        price = await stripe.prices.retrieve(paymentDoc[0]?.priceId);
        // Retrieve the product name
        product = await stripe.products.retrieve(price?.product);
        productName = product.name;
      }
      payload = {
        googlePayId: null,
        applePayId: null,
        subscribeScheduleId : paymentDoc[0]?.subscribeScheduleId,
        priceId : paymentDoc[0]?.priceId,
        current_phase : paymentDoc[0]?.current_phase,
        planName: productName || ""
        // planName: price?.metadata?.name || ""
      }
    } else {
      if (paymentDoc[0]?.googlePayId || paymentDoc[0]?.applePayId) {
        let price = {};
        let product;
        let productName;
        if (paymentDoc[0]?.priceId) {
          price = await stripe.prices.retrieve(paymentDoc[0]?.priceId);
          // Retrieve the product name
          product = await stripe.products.retrieve(price?.product);
          productName = product.name;
        }
        payload = {
          googlePayId: paymentDoc[0]?.googlePayId,
          applePayId: paymentDoc[0]?.applePayId,
          subscribeScheduleId: null,
          priceId: paymentDoc[0]?.priceId,
          current_phase: paymentDoc[0]?.current_phase,
          planName: productName || ""
          // planName: price?.metadata?.name || ""
        };

      } else {
        let price = {};
        let product;
        let productName;
        if (paymentDoc[0]?.priceId) {
          price = await stripe.prices.retrieve(paymentDoc[0]?.priceId);
          // Retrieve the product name
          product = await stripe.products.retrieve(price?.product);
          productName = product.name;
        }
        // let endDate = new Date(price?.created * 1000);
        // price?.created ?
        //     price?.recurring?.interval === "month" ? endDate.setMonth(endDate.getMonth() + price?.recurring?.interval_count) :
        //         endDate.setMonth(endDate.getMonth() + price?.recurring?.interval_count * 12): "";
        payload = {                                                   
          // googlePayId: null,
          // applePayId: null,
          // subscribeScheduleId: null,
          // priceId: price?.id,
          // current_phase: {
          //   startDate: price?.created ? new Date(price?.created * 1000).toISOString() : "",
          //   endDate: endDate,
          // },
          // planName: productName || ""
          // planName: price?.metadata?.name || ""
        };
      
      }
    }
  }
  return payload || {};
}

async function addOrUpdateDeviceTokens(user_id, data) {
  const userTokens = await UserToken.get({user_id: user_id});
  for (const item of userTokens) {
    if(item.device_id !== data.device_id) {
      await UserToken.update(
          { _id: item?._id },
          {
            is_loggedOut: true,
            loggedOut_at: new Date().toISOString(),
          }
      );
    }
  }
  const deviceExist = await UserToken.get({
    user_id: user_id,
    device_id: data.device_id,
    is_deleted: false,
  });
  if (deviceExist.length) {
    await UserToken.update(
      { user_id, device_id: data.device_id, is_deleted: false },
      {
        device_token: data.device_token,
        is_loggedOut: false,
        loggedOut_at: new Date().toISOString(),
      }
    );
  } else {
    await UserToken.add({
      device_id: data.device_id,
      device_token: data.device_token,
      device_type: data.device_type,
      user_id: user_id,
    });
  }
}

async function uploadFileAndUpdateProfileURL(s3Location, file, filter) {
  uploadFileToS3(process.env.Aws_Bucket_Name, s3Location, file).then(
    async (result) => {
      await User.update(filter, { profile_image: s3Location });
    },
    (err) => {
      logger.log(level.error, `updateUserDetail err=${beautify(err.message)}`);
    }
  );
}

export const makePayment = async (request, response) => {
  try {
    let data = request.body;
  } catch (error) {}
};
