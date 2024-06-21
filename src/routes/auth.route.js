import { Router } from 'express';
import {
  signUp,
  login,
  forgotPassword,
  phoneExists,
  getUserByID,
  resetPasswordCheckLink,
  updatePassword,
  resetPasswordLinkExpirePage,
  passwordUpdatedPage,
  resetPasswordPage,
  passwordUpdateFailedPage,
  updateUserDetail,
  verifyOTP,
  resendOTP,
  logout,
} from '../controllers/authentication.controller.js';
import {
  authMiddleware,
  verifyMiddleware,
} from '../shared/middleweres/auth.middlewere.js';

import multer from 'multer';
import { makePayment } from '../controllers/payment.controller.js';
const upload = multer();
const routes = new Router();
const Path = {
  login: '/login',
  logout: '/logout',
  makePayment: '/makePayment',
  register: '/register',
  verifyOTP: '/verifyOTP',
  resendOTP: '/resendOTP',
  forgotPasswprd: '/forgot-password',
  phoneExists: '/phone-exists',
  userByID: '/user',
  resetPasswordCheckLink: '/users/check/mail/:email/:mailid/:time',
  updatePassword: '/users/password/:email/:password',
  updateUserDetail: '/user',
  // Pages
  resetPasswordPage: '/:email/password/:time/:mailid/:tc',
  resetPasswordLinkExpiredPage: '/users/link/expired',
  passwordUpdatedPage: '/users/:email/success',
  passwordUpdateFailedPage: '/users/:email/failure',
};

// Pages
routes.get(Path.resetPasswordPage, resetPasswordPage);
routes.get(Path.resetPasswordLinkExpiredPage, resetPasswordLinkExpirePage);
routes.get(Path.passwordUpdatedPage, passwordUpdatedPage);
routes.get(Path.passwordUpdateFailedPage, passwordUpdateFailedPage);
routes.use(verifyMiddleware);
routes.post(Path.register, upload.single('file'), signUp);
routes.post(Path.verifyOTP, verifyOTP);
routes.post(Path.resendOTP, resendOTP);
routes.post(Path.login, login);
routes.post(Path.logout, logout);
routes.post(Path.makePayment, makePayment);
routes.post(Path.phoneExists, phoneExists);
routes.post(Path.forgotPasswprd, forgotPassword);
routes.get(Path.resetPasswordCheckLink, resetPasswordCheckLink);
routes.post(Path.updatePassword, updatePassword);
// Auth Token Gateway
routes.use(authMiddleware);
routes.put(Path.updateUserDetail, upload.single('file'), updateUserDetail);
routes.get(Path.userByID, getUserByID);
export default routes;
