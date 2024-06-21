import { Router } from "express";
import { authMiddleware } from "../shared/middleweres/auth.middlewere.js";
import { getIntroVideoList } from "../controllers/introVideo.controller.js";

const routes = new Router();
const Path = {
  getList: "/",
};

// Auth Token Gateway
routes.use(authMiddleware);

routes.get(Path.getList, getIntroVideoList);

export default routes;
