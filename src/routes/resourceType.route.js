import { Router } from "express";
import { authMiddleware } from "../shared/middleweres/auth.middlewere.js";
import {getResourceTypeForUser} from "../controllers/resource.controller.js";

const routes = new Router();
const Path = {
    getResourceType: "/get-resourceType",
};

// Auth Token Gateway
routes.use(authMiddleware);

routes.get(Path.getResourceType, getResourceTypeForUser);

export default routes;
