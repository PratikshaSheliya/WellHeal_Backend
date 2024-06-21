import { Router } from "express";
import { authMiddleware } from "../shared/middleweres/auth.middlewere.js";
import { getQuoteImage } from "../controllers/quote.controller.js";

const routes = new Router();
const Path = {
  getQuote: "/get-daily-quote",
};

// Auth Token Gateway
routes.use(authMiddleware);

routes.get(Path.getQuote, getQuoteImage);

export default routes;
