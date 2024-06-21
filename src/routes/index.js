import { Router } from "express";
import AuthRoutes from "./auth.route.js";
import AdminRoutes from "./admin.route.js";
import QuestionRoutes from "./question.route.js";
import CategoryRoutes from "./category.route.js";
import TherapyRoutes from "./therapy.route.js";
import ResourceRoutes from "./resource.route.js";
import IntroVideoRoutes from "./introVideo.route.js";
import UserRoutes from "./user.route.js";
import QuoteRoutes from "./quote.route.js";
import NotificationRoutes from "./notification.route.js";
import PaymentRoutes from "./payment.route.js";
import resourceTypeRoutes from "./resourceType.route.js";
import subscribeCardRoutes from "./suubscribeCard.route.js"
import subscribePaymentCardRoutes from "./subscribePaymentCard.route.js"
import { verifyMiddleware } from "../shared/middleweres/auth.middlewere.js";

const routes = new Router();
const Path = {
  auth: "/auth",
  question: "/question",
  admin: "/admin",
  category: "/category",
  therapy: "/therapy",
  resource: "/resource",
  introVideo: "/intro",
  user: "/user",
  quote: "/quote",
  notification: "/notification",
  payment: "/stripe",
  resourceType: "/resource_type",
  subscribeCard: "/subscribeCard",
  subscribePaymentCard: "/subscribePaymentCard"
};

routes.use(Path.admin, AdminRoutes);
routes.use(Path.auth, AuthRoutes);

routes.use(verifyMiddleware);

routes.use(Path.question, QuestionRoutes);
routes.use(Path.category, CategoryRoutes);
routes.use(Path.therapy, TherapyRoutes);
routes.use(Path.resource, ResourceRoutes);
routes.use(Path.introVideo, IntroVideoRoutes);
routes.use(Path.user, UserRoutes);
routes.use(Path.quote, QuoteRoutes);
routes.use(Path.notification, NotificationRoutes);
routes.use(Path.payment, PaymentRoutes);
routes.use(Path.resourceType, resourceTypeRoutes);
routes.use(Path.subscribeCard, subscribeCardRoutes);
routes.use(Path.subscribePaymentCard, subscribePaymentCardRoutes);

export default routes;
