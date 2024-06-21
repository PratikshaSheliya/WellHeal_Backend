import { Router } from "express";
import { authMiddleware } from "../shared/middleweres/auth.middlewere.js";
import {getNotification} from "../controllers/notification.controller.js";

const routes = new Router();
const Path = {
    getNotification: "/get-notification/:userId",
};

// Auth Token Gateway
routes.use(authMiddleware);

routes.get(Path.getNotification, getNotification);

export default routes;
