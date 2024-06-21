import jwt from "jsonwebtoken";
import { logger, level } from "./../../../config/logger.js";
import { constants } from "./../../constant/jwt_auth.const.js";
import { OAuth2Client } from "google-auth-library";
import { decrypt } from "./../../utils/utility.js";

class JWTAuth {
  async createToken(email, userId = null) {
    return new Promise((resolve, reject) => {
      const exp =
        Math.floor(Date.now() / 1000) +
        60 * 60 * (24 * constants.TOKEN_EXPIRES_IN_DAY); // 1 day
      const payload = {
        email: email,
        userId,
        exp,
      };
      try {
        let secret = process.env.JWT_TOKEN_SECRET;
        const token = Promise.resolve(jwt.sign(payload, secret));
        resolve(token);
      } catch (err) {
        reject(err);
      }
    });
  }

  async createAdminToken(email, adminId) {
    return new Promise((resolve, reject) => {
      // const exp =
      //   Math.floor(Date.now() / 1000) +
      //   60 * 60 * (24 * constants.ADMIN_TOKEN_EXPIRES_IN_DAY); // 1 day

      const exp = Math.floor(Date.now() / 1000) + (60 * 60 * 24 * 365); // 365 days
      const payload = {
        email: email,
        userId: adminId,
        exp,
      };
      try {
        let secret = process.env.JWT_ADMIN_TOKEN_SECRET;
        const token = Promise.resolve(jwt.sign(payload, secret));
        resolve(token);
      } catch (err) {
        reject(err);
      }
    });
  }

  async verifyToken(accessToken) {
    return new Promise((resolve, reject) => {
      try {
        let secret = process.env.JWT_TOKEN_SECRET;
        const decoded = jwt.verify(accessToken, secret);
        resolve(decoded);
      } catch (err) {
        reject(err);
      }
    });
  }

  async verifyAdminToken(accessToken) {
    console.log("accessToken ************ ", accessToken)
    logger.log(
      level.debug,
      `verifyAdminToken  decoded=${JSON.stringify(accessToken)}`
    );
    return new Promise((resolve, reject) => {
      try {
        let secret = process.env.JWT_ADMIN_TOKEN_SECRET;
        const decoded = jwt.verify(accessToken, secret);
        logger.log(
          level.debug,
          `verifyAdminToken  decoded=${JSON.stringify(decoded)}`
        );
        resolve(decoded);
      } catch (err) {
        reject(err);
      }
    });
  }

  async verifyGoogleIdToken(idToken) {
    logger.log(level.debug, `verifyGoogleIdToken: ${idToken}`);
    const clientId = decrypt(constants.GOOGLE_LOGIN_CLIENT_ID);
    const client = new OAuth2Client(clientId);
    const ticket = await client.verifyIdToken({
      idToken: idToken,
      // audience: clientId
    });
    const payload = await ticket.getPayload();
    logger.log(level.info, `Google Token Payload : ${JSON.stringify(payload)}`);
    if (payload["aud"] == clientId) {
      // User is fully authenticate with google login
      payload["social_id"] = payload["sub"];
      return payload;
    }
    return null;
  }
}
export default JWTAuth;
