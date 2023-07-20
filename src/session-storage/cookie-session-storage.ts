import { CognitoClient, Session } from "../cognito-client.js";
import { ISessionStorage } from "./session-storage.js";
import Cookies from "js-cookie";

export interface CookieSessionStorageOptions {
  cookieName: string;
  /**
   * Define when the cookie will be removed. Value can be a Number
   * which will be interpreted as days from time of creation or a
   * Date instance. If omitted, the cookie becomes a session cookie.
   */
  expires?: number | Date | undefined;

  /**
   * Define the path where the cookie is available. Defaults to '/'
   */
  path?: string | undefined;

  /**
   * Define the domain where the cookie is available. Defaults to
   * the domain of the page where the cookie was created.
   */
  domain?: string | undefined;

  /**
   * A Boolean indicating if the cookie transmission requires a
   * secure protocol (https). Defaults to false.
   */
  secure?: boolean | undefined;

  /**
   * Asserts that a cookie must not be sent with cross-origin requests,
   * providing some protection against cross-site request forgery
   * attacks (CSRF)
   */
  sameSite?: "strict" | "Strict" | "lax" | "Lax" | "none" | "None" | undefined;
}

export class CookieSessionStorage extends ISessionStorage {
  private accessTokenCookieName: string;
  private idTokenCookieName: string;
  private refreshTokenCookieName: string;
  private expiresInCookieName: string;

  constructor(
    client: CognitoClient,
    private options: CookieSessionStorageOptions
  ) {
    super(client);

    this.accessTokenCookieName = `${this.options.cookieName}_accessToken`;
    this.idTokenCookieName = `${this.options.cookieName}_idToken`;
    this.refreshTokenCookieName = `${this.options.cookieName}_refreshToken`;
    this.expiresInCookieName = `${this.options.cookieName}_expiresIn`;
  }

  async getSession(): Promise<Session | undefined> {
    const accessToken = Cookies.get(this.accessTokenCookieName);
    const idToken = Cookies.get(this.idTokenCookieName);
    const refreshToken = Cookies.get(this.refreshTokenCookieName);
    const expiresIn = Cookies.get(this.expiresInCookieName);

    if (!accessToken || !idToken || !refreshToken || !expiresIn) {
      return undefined;
    }

    const session = {
      accessToken,
      idToken,
      refreshToken,
      expiresIn: Number.parseFloat(expiresIn),
    };

    return this.refreshSession(session);
  }
  setSession(session: Session | undefined): void {
    if (session === undefined) {
      Cookies.remove(this.accessTokenCookieName);
      Cookies.remove(this.idTokenCookieName);
      Cookies.remove(this.refreshTokenCookieName);
      Cookies.remove(this.expiresInCookieName);
      return;
    }

    Cookies.set(this.accessTokenCookieName, session.accessToken, this.options);
    Cookies.set(this.idTokenCookieName, session.idToken, this.options);
    Cookies.set(
      this.refreshTokenCookieName,
      session.refreshToken,
      this.options
    );
    Cookies.set(
      this.expiresInCookieName,
      session.expiresIn.toString(),
      this.options
    );
  }
}
