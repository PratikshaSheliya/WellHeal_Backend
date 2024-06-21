import { Router } from "express";
import { createSplashScreenAnswer, getSplashScreenQuestion } from "../controllers/question.controller.js";
import { authMiddleware } from "../shared/middleweres/auth.middlewere.js";

const routes = new Router();
const Path = {
  getQuestion: "/get-splash-questions",
  splashScreenAnswer: "/answer"
};

routes.get(Path.getQuestion, getSplashScreenQuestion);

// Auth Token Gateway
routes.use(authMiddleware);


routes.post(Path.splashScreenAnswer, createSplashScreenAnswer);

export default routes;
