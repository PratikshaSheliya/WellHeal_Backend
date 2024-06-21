import { Router } from "express";
import { authMiddleware } from "../shared/middleweres/auth.middlewere.js";
import { getCategory, getSubCategory } from "../controllers/category.controller.js";

const routes = new Router();
const Path = {
  category: "/",
  subCategory: "/sub/:catId?",
};

routes.get(Path.subCategory, getSubCategory)

// Auth Token Gateway
routes.use(authMiddleware);

routes.get(Path.category, getCategory);

export default routes;
