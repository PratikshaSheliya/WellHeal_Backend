import { Router } from "express";
import multer from 'multer';

import { signUp, adminLogin, getAllUsers, createFAQContent, updateFAQContent, deleteFAQContent, getFAQContent, updatePrivacyPolicy, createPrivacyPolicy, deletePrivacyPolicy, getPrivacyPolicy, changeUserStatus, updateProfile, getAnalytics, getAverageTherapyRating,deleteUser, createSplashScreenContent, updateSplashScreenContent, deleteSplashScreenContent, getSplashScreenContent, createHomeScreenImage, updateHomeScreenImage, deleteHomeScreenImage, getHomeScreenImage, createAppVersion, updateAppVersion, deleteAppVersion, getAppVersion, downloadUserReport, getAllNotification, getAllScheduleNotification, updateScheduleNotification, deleteScheduleNotification ,getApplicationVersion,updateApplicationVersion,createFreeUserTrail, getAllFreeUserTrail,updateFreeUserTrail  } from "../controllers/admin.controller.js";
import { createQuestion, deleteQuestion, getSplashScreenQuestion, updateQuestion } from "../controllers/question.controller.js";
import { createCategory, createSubCategory, deleteCategory, deleteSubCategory, getCategory, getSubCategoriesForAdmin, updateCategory, updateSubCategory } from "../controllers/category.controller.js";
import { createIntroVideo, createResource, createResourceForSubCategory, createResourceType, deleteIntroVideo, deleteResource, deleteResourceForSubCategory, deleteResourceType, getResourceByTherapy, getResourceForSubCategory, getResourceTypes, linkResourceToTherapy, unlinkResourceToTherapy, updateIntroVideo, updateResource, updateResourceForSubCategory, updateResourceType, createResourceForAffirmation, updateResourceForAffirmation, deleteResourceForAffirmation, getResourceForAffirmation  } from "../controllers/resource.controller.js";
import { adminAuthMiddleware, verifyMiddleware } from "../shared/middleweres/auth.middlewere.js";
import { createTherapy, deleteTherapy, getAllTherapyForAdmin, linkTherapyToSubCategory, unlinkTherapyToSubCategory, updateTherapy } from "../controllers/therapy.controller.js";
import { getIntroVideoList } from "../controllers/introVideo.controller.js";
import { getCoupons, updateTrialCoupons } from "../controllers/coupon.controller.js";
import { sendNotificationToUser } from "../controllers/user.controller.js";
// import { createCoupon } from "../controllers/coupon.controller.js";

import { createQuote, updateQuote, getAllQuote, deleteQuote } from "../controllers/quote.controller.js";
import {createSubscribeCard, getSubscribeCard, updateSubscribeCard, deleteSubscribeCard} from "../controllers/subscribe.controller.js";
import {createSubscribePaymentCard, getSubscribePaymentCard, updateSubscribePaymentCard, deleteSubscribePaymentCard} from "../controllers/subscribePayment.controller.js";
import {getAllPriceList, updatePrice} from "../controllers/payment.controller.js";

const routes = new Router();
const upload = multer();

const Path = {
  login: "/login",
  register: "/register",
  changeStatus: "/user/status/:userId",
  updateProfile: "/profile-update",

  getAllUsers: "/users",
  getAnalytics: "/analytics",
  getAverageTherapyRating: "/average-therapy-rating",
  deleteUser:"/remove-account/:userId",

  createQuestion: "/create-question",
  updateQuestion: "/update-question/:questionId",
  deleteQuestion: "/delete-question/:questionId",
  getQuestion: "/get-splash-questions",

  getAllResources: "/resource/:therapyId?",
  createResource: "/resource",
  deleteResource: "/resource/:resourceId",
  updateResource: "/resource/:resourceId",
  linkResourceToTherapy: "/resource/link/:resourceId",
  unlinkResourceToTherapy: "/resource/unlink/:resourceId",
  createResourceType: "/resource-type",
  deleteResourceType: "/resource-type/:resourceTypeId",
  updateResourceType: "/resource-type/:resourceTypeId",
  getResourceTypes: "/resource-type",
  getResourceForSubCategory: "/sub-category/resource/:subCategoryId?",
  addResourceForSubCategory: "/sub-category/resource",
  updateResourceForSubCategory: "/sub-category/resource/:resourceId",
  deleteResourceForSubCategory: "/sub-category/resource/:resourceId",

  getAllCategory: "/category",
  createCategory: "/category",
  updateCategory: "/category/:catId",
  deleteCategory: "/category/:catId",
  getAllSubCategory: "/sub-category/:catId?",
  createSubCategory: "/sub-category",
  updateSubCategory: "/sub-category/:subCatId",
  deleteSubCategory: "/sub-category/:subCatId",

  getAllTherapy: "/therapy/:subCatId?",
  createTherapy: "/therapy",
  updateTherapy: "/therapy/:therapyId",
  deleteTherapy: "/therapy/:therapyId",
  linkTherapyToSubCategory: "/therapy/link/:therapyId",
  unlinkTherapyToSubCategory: "/therapy/unlink/:therapyId",

  getIntroVideo: "/intro",
  createIntroVideo: "/intro",
  updateIntroVideo: "/intro/:introId",
  deleteIntroVideo: "/intro/:introId",

  getFAQContent: "/faq",
  createFAQContent: "/faq",
  updateFAQContent: "/faq/:faqId",
  deleteFAQContent: "/faq/:faqId",

  createPrivacyPolicy: "/privacy-policy",
  getPrivacyPolicy: "/privacy-policy/:content_type?",
  updatePrivacyPolicy: "/privacy-policy/:recordId/:content_type?",
  deletePrivacyPolicy: "/privacy-policy/:recordId/:content_type?",

  getSplashScreenContent: "/splash-content",
  createSplashScreenContent: "/splash-content",
  updateSplashScreenContent: "/splash-content/:splashContentId",
  deleteSplashScreenContent: "/splash-content/:splashContentId",

  createHomeScreenImage: "/home/images",
  getHomeScreenImage: "/home/images",
  updateHomeScreenImage: "/home/images/:slugId",
  deleteHomeScreenImage: "/home/images/:slugId",

  getAppVersion: "/app-version/:content_type?",
  createAppVersion: "/app-version",
  updateAppVersion: "/app-version/:slugId",
  deleteAppVersion: "/app-version/:slugId/:content_type",

  downloadUserReport: "/download-user-report",

  // createCoupon: "/coupon",
  getCoupons: "/coupons",
  // updateCoupon: "/coupon/:couponId",
  updateTrialCoupons: "/coupons/trial/update",
  // deleteCoupon: "/coupon/:couponId",

  sendNotificationToUser: "/notification/send",
  getAllNotification: "/notification/get",
  getAllScheduleNotification: "/scheduleNotification/get",
  updateScheduleNotification: "/updateScheduleNotification/:scheduleNotificationId",
  deleteScheduleNotification: "/deleteScheduleNotification/:scheduleNotificationId",

  getQuote: "/get-quote",
  createQuote: "/create-quote",
  updateQuote: "/update-quote/:quoteId",
  deleteQuote: "/delete-quote/:quoteId",

  createSubscribeCard: "/create-subscribeCard",
  getSubscribeCard: "/get-subscribeCard",
  updateSubscribeCard: "/update-subscribeCard/:subscribeCardId",
  deleteSubscribeCard: "/delete-subscribeCard/:subscribeCardId",

  createSubscribePaymentCard: "/create-subscribePaymentCard",
  getSubscribePaymentCard: "/get-subscribePaymentCard",
  updateSubscribePaymentCard: "/update-subscribePaymentCard/:subscribePaymentCardId",
  deleteSubscribePaymentCard: "/delete-subscribePaymentCard/:subscribePaymentCardId",

  getApplicationVersion: "/application-version/",
  updateApplicationVersion: "/application-version/:appVersionId",
  
  updatePrice: '/update-price/:priceId',
  getAllPriceList: '/getAll-priceList',
  
  createFreeUserTrail: "/create-free-trial/",
  updateFreeUserTrail: "/update-free-trial/:userId",
  getAllFreeUserTrail: "/free-trial-users/",

  addResourceForAffirmation: "/affirmation/resource",
  getResourceForAffirmation: "/affirmation/resource/:subCategoryId?",
  updateResourceForAffirmation: "/affirmation/resource/:resourceId",
  deleteResourceForAffirmation: "/affirmation/resource/:resourceId",
};

routes.post(Path.downloadUserReport, downloadUserReport)

routes.use(verifyMiddleware);

routes.post(Path.register, signUp);
routes.post(Path.login, adminLogin);

routes.use(adminAuthMiddleware);


routes.get(Path.getAnalytics, getAnalytics);
routes.get(Path.getAverageTherapyRating, getAverageTherapyRating);
routes.get(Path.getAllUsers, getAllUsers);
routes.get(Path.getResourceTypes, getResourceTypes);
routes.get(Path.getFAQContent, getFAQContent);
routes.get(Path.getPrivacyPolicy, getPrivacyPolicy);
routes.get(Path.getAllCategory, getCategory);
routes.get(Path.getResourceForSubCategory, getResourceForSubCategory);   // Keep this uppper then path.getAllSubCategory. otherwise it will not match correct route
routes.get(Path.getAllSubCategory, getSubCategoriesForAdmin);
routes.get(Path.getAllTherapy, getAllTherapyForAdmin);
routes.get(Path.getSplashScreenContent, getSplashScreenContent);
routes.get(Path.getAllResources, getResourceByTherapy);
routes.get(Path.getIntroVideo, getIntroVideoList);
routes.get(Path.getQuestion, getSplashScreenQuestion);
routes.get(Path.getHomeScreenImage, getHomeScreenImage);
routes.get(Path.getAppVersion, getAppVersion);
routes.get(Path.getCoupons, getCoupons);
routes.get(Path.getAllNotification, getAllNotification);
routes.get(Path.getAllScheduleNotification, getAllScheduleNotification);
routes.get(Path.getApplicationVersion, getApplicationVersion);
routes.get(Path.getAllFreeUserTrail, getAllFreeUserTrail);
routes.get(Path.getResourceForAffirmation, getResourceForAffirmation);   // Keep this uppper then path.getAllSubCategory. otherwise it will not match correct route


routes.post(Path.createQuestion, upload.single('file'), createQuestion);
routes.post(Path.createCategory, createCategory);
// routes.post(Path.createSubCategory, upload.single('file'), createSubCategory);
routes.post(Path.createSubCategory, upload.fields([{ name: 'file', maxCount: 1 },{ name: 'zoneimage', maxCount: 1 }, { name: 'affirmationzoneimge', maxCount: 1 }]), createSubCategory);
routes.post(Path.createTherapy, upload.single('file'), createTherapy);
routes.post(Path.createResource, upload.fields([{ name: 'resource', maxCount: 1 }, { name: 'thumbnail', maxCount: 1 }]), createResource);
routes.post(Path.createResourceType, createResourceType);
routes.post(Path.createIntroVideo, upload.fields([{ name: 'resource', maxCount: 1 }, { name: 'thumbnail', maxCount: 1 }]), createIntroVideo)
routes.post(Path.createFAQContent, createFAQContent);
routes.post(Path.createPrivacyPolicy, createPrivacyPolicy);
routes.post(Path.addResourceForSubCategory, upload.fields([{ name: 'resource', maxCount: 1 }, { name: 'thumbnail', maxCount: 1 }]), createResourceForSubCategory);
routes.post(Path.createSplashScreenContent, upload.single('file'), createSplashScreenContent);
routes.post(Path.createHomeScreenImage, upload.single('file'), createHomeScreenImage);
routes.post(Path.createAppVersion, createAppVersion);
routes.post(Path.sendNotificationToUser, upload.single('file'), sendNotificationToUser);
// routes.post(Path.createCoupon, createCoupon);
routes.post(Path.createFreeUserTrail, createFreeUserTrail);
routes.post(Path.addResourceForAffirmation, upload.fields([{ name: 'resource', maxCount: 1 }, { name: 'thumbnail', maxCount: 1 }]), createResourceForAffirmation);



routes.put(Path.updateQuestion, upload.single('file'), updateQuestion);
routes.put(Path.updateResourceType, updateResourceType);
routes.put(Path.updateResource, upload.fields([{ name: 'resource', maxCount: 1 }, { name: 'thumbnail', maxCount: 1 }]), updateResource);
routes.put(Path.updateTherapy, upload.single('file'), updateTherapy);
routes.put(Path.updateCategory, updateCategory);
// routes.put(Path.updateSubCategory, upload.single('file'), updateSubCategory);
routes.put(Path.updateSubCategory, upload.fields([{ name: 'file', maxCount: 1 },{ name: 'zoneimage', maxCount: 1 }, { name: 'affirmationzoneimge', maxCount: 1 }]), updateSubCategory);
routes.put(Path.linkResourceToTherapy, linkResourceToTherapy);
routes.put(Path.unlinkResourceToTherapy, unlinkResourceToTherapy);
routes.put(Path.linkTherapyToSubCategory, linkTherapyToSubCategory);
routes.put(Path.unlinkTherapyToSubCategory, unlinkTherapyToSubCategory);
routes.put(Path.updateIntroVideo, upload.fields([{ name: 'resource', maxCount: 1 }, { name: 'thumbnail', maxCount: 1 }]), updateIntroVideo);
routes.put(Path.updateFAQContent, updateFAQContent);
routes.put(Path.updatePrivacyPolicy, updatePrivacyPolicy);
routes.put(Path.changeStatus, changeUserStatus);
routes.put(Path.updateProfile, updateProfile);
routes.put(Path.updateResourceForSubCategory, upload.fields([{ name: 'resource', maxCount: 1 }, { name: 'thumbnail', maxCount: 1 }]), updateResourceForSubCategory);
routes.put(Path.updateSplashScreenContent, upload.single('file'), updateSplashScreenContent);
routes.put(Path.updateHomeScreenImage, upload.single('file'), updateHomeScreenImage);
routes.put(Path.updateAppVersion, updateAppVersion);
routes.put(Path.updateTrialCoupons, updateTrialCoupons);
routes.put(Path.updateScheduleNotification, upload.single('file'), updateScheduleNotification);
routes.put(Path.updateApplicationVersion, updateApplicationVersion);
routes.put(Path.updateFreeUserTrail, updateFreeUserTrail);
routes.put(Path.updateResourceForAffirmation, upload.fields([{ name: 'resource', maxCount: 1 }, { name: 'thumbnail', maxCount: 1 }]), updateResourceForAffirmation);


routes.delete(Path.deleteQuestion, deleteQuestion);
routes.delete(Path.deleteUser, deleteUser);
routes.delete(Path.deleteSubCategory, deleteSubCategory);
routes.delete(Path.deleteCategory, deleteCategory);
routes.delete(Path.deleteTherapy, deleteTherapy);
routes.delete(Path.deleteResource, deleteResource);
routes.delete(Path.deleteResourceType, deleteResourceType);
routes.delete(Path.deleteFAQContent, deleteFAQContent);
routes.delete(Path.deletePrivacyPolicy, deletePrivacyPolicy);
routes.delete(Path.deleteResourceForSubCategory, deleteResourceForSubCategory);
routes.delete(Path.deleteIntroVideo, deleteIntroVideo);
routes.delete(Path.deleteSplashScreenContent, deleteSplashScreenContent);
routes.delete(Path.deleteHomeScreenImage, deleteHomeScreenImage);
routes.delete(Path.deleteAppVersion, deleteAppVersion);
routes.delete(Path.deleteScheduleNotification, deleteScheduleNotification);
routes.delete(Path.deleteResourceForAffirmation, deleteResourceForAffirmation);

routes.get(Path.getQuote, getAllQuote);
routes.post(Path.createQuote, upload.single('file'), createQuote);
routes.put(Path.updateQuote,  upload.single('file'), updateQuote);
routes.delete(Path.deleteQuote, deleteQuote);

routes.post(Path.createSubscribeCard, upload.single('file'), createSubscribeCard);
routes.get(Path.getSubscribeCard, getSubscribeCard);
routes.put(Path.updateSubscribeCard,  upload.single('file'), updateSubscribeCard);
routes.delete(Path.deleteSubscribeCard, deleteSubscribeCard);

routes.post(Path.createSubscribePaymentCard, createSubscribePaymentCard);
routes.get(Path.getSubscribePaymentCard, getSubscribePaymentCard);
routes.put(Path.updateSubscribePaymentCard, updateSubscribePaymentCard);
routes.delete(Path.deleteSubscribePaymentCard, deleteSubscribePaymentCard);

routes.put(Path.updatePrice, updatePrice);
routes.get(Path.getAllPriceList, getAllPriceList);

export default routes;
