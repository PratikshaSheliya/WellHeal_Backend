import { Router } from "express";
import { authMiddleware } from "../shared/middleweres/auth.middlewere.js";
import { addTherapyReviewRating, getUserTherapiesWithProgress, getRecentTherapy, getRecommendedTherapyList, getTherapiesList, getTherapyReviewRatings } from "../controllers/therapy.controller.js";

const routes = new Router();
const Path = {
  therapy: "/",
  onGoing: "/going/list",
  recommended: "/recommended",
  addReviewRating: "/rating",
  getReviewRatingList: "/rating/:therapyId",
  getTherapiesList: "/list"
};

// Auth Token Gateway
routes.use(authMiddleware);

routes.get(Path.therapy, getRecentTherapy);
routes.get(Path.onGoing, getUserTherapiesWithProgress);
routes.get(Path.recommended, getRecommendedTherapyList);
routes.get(Path.getReviewRatingList, getTherapyReviewRatings);
routes.get(Path.getTherapiesList, getTherapiesList);

routes.post(Path.addReviewRating, addTherapyReviewRating);

export default routes;
