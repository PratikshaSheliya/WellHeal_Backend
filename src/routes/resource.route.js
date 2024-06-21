import { Router } from "express";
import { getFAQContent, getPrivacyPolicy, getSplashScreenContent } from "../controllers/admin.controller.js";
import { getResourceByType, makeFavoriteAndUnfavorite, getResourceByTherapy, updateUserResourceProgress, addResourceReviewRating, getResourceReviewRatings, getResourceForSubCategory, getResourceForAffirmation, getAffirmationSubcategoryList } from "../controllers/resource.controller.js";
import { authMiddleware } from "../shared/middleweres/auth.middlewere.js";

const routes = new Router();
const Path = {
  makeFavorite: "/favorite/:id",
  getResourceByType: "/type/:type",
  getResourceByTherapy: "/get/:therapyId?",
  updateResourceProgress: "/progress",
  addReviewRating: "/rating",
  getReviewRatingList: "/rating/:resourceId",
  getResourceForSubCategory: "/sub-category/resource/:subCategoryId?",
  getSplashScreenContent: "/splash-content",
  getFAQContent: "/faq",
  getPrivacyPolicy: "/privacy-policy/:content_type?",
  getResourceForAffirmation: "/affirmation/resource/:subCategoryId?",
  getAffirmationSubcategoryList: "/affirmation/subcategorylist/:subCategoryId?",
};

routes.get(Path.getSplashScreenContent, getSplashScreenContent);

// Auth Token Gateway
routes.use(authMiddleware);

routes.get(Path.makeFavorite, makeFavoriteAndUnfavorite);
routes.get(Path.getResourceByType, getResourceByType);
routes.get(Path.getResourceByTherapy, getResourceByTherapy);
routes.get(Path.getReviewRatingList, getResourceReviewRatings);
routes.get(Path.getResourceForSubCategory, getResourceForSubCategory);
routes.get(Path.getFAQContent, getFAQContent);
routes.get(Path.getPrivacyPolicy, getPrivacyPolicy);
routes.get(Path.getResourceForAffirmation, getResourceForAffirmation);
routes.get(Path.getAffirmationSubcategoryList, getAffirmationSubcategoryList);

routes.post(Path.addReviewRating, addResourceReviewRating);

routes.put(Path.updateResourceProgress, updateUserResourceProgress);

export default routes;
