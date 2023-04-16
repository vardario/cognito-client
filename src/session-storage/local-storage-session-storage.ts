import { Session } from '../cognito-client';
import { OAuthVerificationParams, SessionStorage } from './session-storage';

export interface LocalStorageSessionStorageProps {
  storageName: string;
}

/**
 * LocalStorage based session storage.
 * This session storage works only one domain at a time.
 * @see https://developer.mozilla.org/en-US/docs/Web/API/Window/localStorage
 * Use @see CookieSessionStorage for a session storage, which
 * can span across sub domains as well.
 */
export class LocalStorageSessionStorage extends SessionStorage {
  private readonly props: LocalStorageSessionStorageProps;

  constructor(props: LocalStorageSessionStorageProps) {
    super();

    this.props = props;
  }

  getSession(): Session | undefined {
    const payload = window.localStorage.getItem(this.props.storageName);

    if (payload === null) {
      return undefined;
    }

    return JSON.parse(payload) as Session;
  }
  setSession(session: Session | undefined): void {
    if (session === undefined) {
      window.localStorage.removeItem(this.props.storageName);
      return;
    }
    window.localStorage.setItem(this.props.storageName, JSON.stringify(session));
  }
  setOauthVerificationParams(oAuthParams: OAuthVerificationParams): void {
    window.localStorage.setItem(`${this.props.storageName}_oauth`, JSON.stringify(oAuthParams));
  }
  getOauthVerificationParams(): OAuthVerificationParams | undefined {
    const payload = window.localStorage.getItem(`${this.props.storageName}_oauth`);
    if (payload === null) {
      return undefined;
    }

    return JSON.parse(payload);
  }
}
