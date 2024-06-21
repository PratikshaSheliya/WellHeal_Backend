import { Router } from "express";
import { authMiddleware } from "../shared/middleweres/auth.middlewere.js";
import {getUserSubscribePaymentCard} from "../controllers/subscribePayment.controller.js";

const routes = new Router();
const Path = {
    getSubscribePaymentCard: "/getSubscribePaymentCard",
};

// Auth Token Gateway
routes.use(authMiddleware);

// routes.get(Path.getSubscribePaymentCard, getUserSubscribePaymentCard);

export default routes;