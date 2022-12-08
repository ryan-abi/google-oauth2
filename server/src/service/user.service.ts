import {
  DocumentDefinition,
  FilterQuery,
  QueryOptions,
  UpdateQuery,
} from "mongoose";
import { omit } from "lodash";
import qs from "qs";
import UserModel, { UserDocument } from "../models/user.model";
import config from "config";
import axios from "axios";
import log from "../utils/logger";

export async function createUser(
  input: DocumentDefinition<
    Omit<UserDocument, "createdAt" | "updatedAt" | "comparePassword">
  >
) {
  try {
    const user = await UserModel.create(input);

    return omit(user.toJSON(), "password");
  } catch (e: any) {
    throw new Error(e);
  }
}

export async function validatePassword({
  email,
  password,
}: {
  email: string;
  password: string;
}) {
  const user = await UserModel.findOne({ email });

  if (!user) {
    return false;
  }

  const isValid = await user.comparePassword(password);

  if (!isValid) return false;

  return omit(user.toJSON(), "password");
}

export async function findUser(query: FilterQuery<UserDocument>) {
  return UserModel.findOne(query).lean();
}

interface GoogleTokenResults {
  access_token: string;
  expires_in: string;
  refresh_token: string;
  scope: string;
  id_token: string;
}

interface GoogleUserResults {
  id: string;
  email: string;
  verified_email: string;
  name: string;
  given_name: string;
  family_name: string;
  picture: string;
  locale: string;
}

export async function getGoogleOauthTokens({
  code,
}: {
  code: string;
}): Promise<GoogleTokenResults> {
  const url = "https://oauth2.googleapis.com/token";
  const values = {
    code,
    client_id: config.get("googleClientId"),
    client_secret: config.get("googleClientSecret"),
    redirect_uri: config.get("googleOAuthRedirectUrl"),
    grant_type: "authorization_code",
  };
  console.log({ values });

  try {
    const res = await axios.post<GoogleTokenResults>(
      url,
      qs.stringify(values),
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
      }
    );
    console.log({ res });
    return res.data;
  } catch (err: any) {
    console.log(err);
    log.error(err, "Failed to fetch Google Oauth Tokens");
    throw new Error(err.message);
  }
}

export async function getGoogleUser({
  id_token,
  access_token,
}: {
  id_token: string;
  access_token: string;
}): Promise<GoogleUserResults> {
  try {
    const res = await axios.get<GoogleUserResults>(
      `https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token=${access_token}`,
      {
        headers: {
          Authorization: `Bearer ${id_token}`,
        },
      }
    );
    return res.data;
  } catch (err: any) {
    log.error(err, "Error fetching Google User");
    throw new Error(err.message);
  }
}

export async function findAndUpdateUser(
  query: FilterQuery<UserDocument>,
  update: UpdateQuery<UserDocument>,
  options: QueryOptions = {}
) {
  return UserModel.findOneAndUpdate(query, update, options);
}
