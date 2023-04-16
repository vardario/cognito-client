import { CookieProps, Cookies } from '@vardario/cookies';
import { Session } from '../../cognito-client';
import { OAuthVerificationParams, SessionStorage } from '../session-storage';

export interface CookieSessionStorageProps extends CookieProps {
  cookieName: string;
}

/**
 * Cookies based session storage.
 * This session storage works also across sub domains.
 */
export class CookieSessionStorage extends SessionStorage {
  private readonly props: CookieSessionStorageProps;
  private readonly oAuthParamCookieName: string;
  private readonly sessionCookieName: string;
  private readonly cookies: Cookies;

  constructor(props: CookieSessionStorageProps) {
    super();

    this.props = {
      domain: props.domain,
      path: props.path ?? '/',
      expires: props.expires ?? 365,
      secure: props.secure ?? true,
      sameSite: props.sameSite ?? 'None',
      cookieName: props.cookieName,
    };

    this.cookies = new Cookies(this.props);

    this.sessionCookieName = `${props.cookieName}`;
    this.oAuthParamCookieName = `${props.cookieName}_oauth`;
  }

  getSession(): Session | undefined {
    const session = this.cookies.getCookie(this.sessionCookieName);

    if (session === undefined) {
      return undefined;
    }

    return JSON.parse(session);
  }

  setSession(session: Session | undefined) {
    this.cookies.setCookie(this.sessionCookieName, JSON.stringify(session));
  }

  getOauthVerificationParams(): OAuthVerificationParams | undefined {
    const oAuthParams = this.cookies.getCookie(this.oAuthParamCookieName);

    if (oAuthParams === undefined) {
      return undefined;
    }
    return JSON.parse(oAuthParams);
  }

  setOauthVerificationParams(oAuthParams: OAuthVerificationParams): void {
    this.cookies.setCookie(this.oAuthParamCookieName, JSON.stringify(oAuthParams));
  }
}
