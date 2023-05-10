import { randomBytes } from "crypto";
import { Session } from "../cognito-client.js";
import { setupJsDom } from "../test-utils.js";
import { CookieSessionStorage } from "./cookie-session-storage/index.js";
import { LocalStorageSessionStorage } from "./local-storage-session-storage.js";
import { MemorySessionStorage } from "./memory-session-storage.js";
import { OAuthVerificationParams } from "./session-storage.js";
import { expect, test } from "vitest";

setupJsDom();

const sessionStorages = [
  new MemorySessionStorage(),
  new LocalStorageSessionStorage({ storageName: "session" }),
  new CookieSessionStorage({
    domain: "localhost",
    cookieName: "session",
  }),
];

const session: Session = {
  accessToken: randomBytes(128).toString("base64"),
  expiresIn: 600,
  idToken: randomBytes(128).toString("base64"),
  refreshToken: randomBytes(128).toString("base64"),
};

const oAuthVerificationParams: OAuthVerificationParams = {
  pkce: randomBytes(128).toString("base64"),
  state: randomBytes(128).toString("base64"),
};

test("SessionStorage", () => {
  sessionStorages.forEach((sessionStorage) => {
    sessionStorage.setSession(session);
    expect(sessionStorage.getSession()).toStrictEqual(session);

    sessionStorage.setOauthVerificationParams(oAuthVerificationParams);
    expect(sessionStorage.getOauthVerificationParams()).toStrictEqual(
      oAuthVerificationParams
    );
  });
});
