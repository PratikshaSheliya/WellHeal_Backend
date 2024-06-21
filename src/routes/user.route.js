import { Router } from "express";
import multer from "multer";
import { getAppVersion, getHomeScreenImage,getApplicationVersion } from "../controllers/admin.controller.js";
import { checkForTrialEnd } from "../controllers/authentication.controller.js";
import { generateTrialCoupon, verifyTrialCoupon } from "../controllers/coupon.controller.js";
import { getFavouriteTherapies, removeAccount, submitHelpAndFeedback, deepLinking ,deviceidExists } from "../controllers/user.controller.js";
import { authMiddleware } from "../shared/middleweres/auth.middlewere.js";
const upload = multer();

const routes = new Router();
const Path = {
  getFavouriteTherapies: "/fav/therapy",
  submitHelpAndFeedback: "/feedback/submit",
  generateTrialCoupon: "/coupons/trial/create",
  verifyTrialCoupon: "/coupons/trial/verify",
  checkForTrialEnd: "/coupons/trial/check",
  getHomeScreenImage: "/home/images",
  getAppVersion: "/app-version",
  removeAccount: "/remove-account",
  deepLinking: "/deepLinking",
  getApplicationVersion: "/application-version",
  deviceidExists: "/deviceidExists",
};

// Auth Token Gateway
routes.get(Path.deviceidExists, deviceidExists);
routes.use(authMiddleware);

routes.get(Path.getFavouriteTherapies, getFavouriteTherapies);
routes.post(Path.submitHelpAndFeedback, upload.single('file'), submitHelpAndFeedback);
routes.post(Path.generateTrialCoupon, generateTrialCoupon);
routes.post(Path.verifyTrialCoupon, verifyTrialCoupon);
routes.get(Path.checkForTrialEnd, checkForTrialEnd);
routes.get(Path.getHomeScreenImage, getHomeScreenImage);
routes.get(Path.getAppVersion, getAppVersion);
routes.get(Path.removeAccount, removeAccount);
routes.get(Path.deepLinking, deepLinking);
routes.get(Path.getApplicationVersion, getApplicationVersion);


routes.delete(Path.removeAccount, removeAccount);
export default routes;