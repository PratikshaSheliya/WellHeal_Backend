import { Router } from "express";
import { authMiddleware } from "../shared/middleweres/auth.middlewere.js";
import {getUserSubscribeCard} from "../controllers/subscribe.controller.js";

const routes = new Router();
const Path = {
    getSubscribeCard: "/getSubscribeCard",
};

// Auth Token Gateway
routes.use(authMiddleware);

routes.get(Path.getSubscribeCard, getUserSubscribeCard);

export default routes;