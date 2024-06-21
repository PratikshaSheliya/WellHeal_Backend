import bodyParser from "body-parser";
import morgan from "morgan";
import passport from "passport";
import cors from "cors";
import path from "path";
import { middleware } from "express-http-context";
// import { handleStripeWebhook } from '../controllers/stripe.controller';
import * as express from "express";
import session from "express-session";
const __dirname = path.resolve();

const MORGAN_DEV_FORMAT = "dev";

export default (app) => {
  app.get("/public/*", (req, res) => {
    res.sendFile(path.join(__dirname, "src", req.url));
  });
  app.use(cors());
  app.use(
    express.json({
      verify: (req, res, buf) => {
        req.rawBody = buf;
      },
    })
  );
  app.use(bodyParser.urlencoded({ extended: true }));
  app.use(session({ secret: "SECRET", resave: true, saveUninitialized: true })); // session secret
  app.use(passport.initialize());
  app.use(passport.session());
  app.use(morgan(MORGAN_DEV_FORMAT));
  app.use(middleware);
};
