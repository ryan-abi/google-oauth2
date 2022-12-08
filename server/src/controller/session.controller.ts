import { CookieOptions, Request, Response } from "express";
import config from "config";
import {
  createSession,
  findSessions,
  updateSession,
} from "../service/session.service";
import {
  findAndUpdateUser,
  getGoogleOauthTokens,
  getGoogleUser,
  validatePassword,
} from "../service/user.service";
import { signJwt } from "../utils/jwt.utils";
import log from "../utils/logger";
import jwt from "jsonwebtoken";

export async function createUserSessionHandler(req: Request, res: Response) {
  // Validate the user's password
  const user = await validatePassword(req.body);

  if (!user) {
    return res.status(401).send("Invalid email or password");
  }

  // create a session
  const session = await createSession(user._id, req.get("user-agent") || "");

  // create an access token

  const accessToken = signJwt(
    { ...user, session: session._id },
    { expiresIn: config.get("accessTokenTtl") } // 15 minutes
  );

  // create a refresh token
  const refreshToken = signJwt(
    { ...user, session: session._id },
    { expiresIn: config.get("refreshTokenTtl") } // 15 minutes
  );

  // return access & refresh tokens

  res.cookie("accessToken", accessToken, {
    maxAge: 900000, // 15 mins
    httpOnly: true,
    domain: "localhost",
    path: "/",
    sameSite: "strict",
    secure: false,
  });

  res.cookie("refreshToken", refreshToken, {
    maxAge: 3.154e10, // 1 year
    httpOnly: true,
    domain: "localhost",
    path: "/",
    sameSite: "strict",
    secure: false,
  });

  return res.send({ accessToken, refreshToken });
}

export async function getUserSessionsHandler(req: Request, res: Response) {
  const userId = res.locals.user._id;

  const sessions = await findSessions({ user: userId, valid: true });

  return res.send(sessions);
}

export async function deleteSessionHandler(req: Request, res: Response) {
  const sessionId = res.locals.user.session;

  await updateSession({ _id: sessionId }, { valid: false });

  return res.send({
    accessToken: null,
    refreshToken: null,
  });
}

export async function googleOauthHandler(req: Request, res: Response) {
  // get code from query string
  const code = req.query.code as string;
  try {
    // get id and access token with the code
    const { id_token, access_token } = await getGoogleOauthTokens({ code });
    console.log({ id_token, access_token });
    // get user with tokens
    // const googleUser = jwt.decode(id_token);
    const googleUser = await getGoogleUser({ id_token, access_token });
    console.log({ googleUser });

    if (!googleUser.email) {
      return res.status(403).send("Google account is not verified");
    }
    // upsert user
    const user = await findAndUpdateUser(
      {
        email: googleUser.email,
      },
      {
        email: googleUser.email,
        name: googleUser.name,
      },
      { upsert: true, new: true }
    );
    // create a session
    const session = await createSession(user._id, req.get("user-agent") || "");

    // create an access token

    const accessToken = signJwt(
      { ...user.toJSON(), session: session._id },
      { expiresIn: config.get("accessTokenTtl") } // 15 minutes
    );

    // create a refresh token
    const refreshToken = signJwt(
      { ...user.toJSON(), session: session._id },
      { expiresIn: config.get("refreshTokenTtl") } // 1 year
    );

    const accessTokenCookiesOptions: CookieOptions = {
      maxAge: 900000, // 15 mins
      httpOnly: true,
      domain: "localhost",
      path: "/",
      sameSite: "lax",
      secure: false,
    };
    const refreshTokenCookiesOptions: CookieOptions = {
      ...accessTokenCookiesOptions,
      maxAge: 3.154e10, // 1 year
    };

    // set cookies
    res.cookie("accessToken", accessToken, accessTokenCookiesOptions);

    res.cookie("refreshToken", refreshToken, refreshTokenCookiesOptions);

    res.redirect(config.get("origin2"));

    // add refresh access_token with refresh Token
    // add sign out
  } catch (err: any) {
    log.error(err.response.data.error, "Auth Failed");
    return res.redirect(`${config.get("origin")}/oauth/error`);
  }
}
