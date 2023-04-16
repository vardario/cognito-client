import { Session } from '../cognito-client';

export interface OAuthVerificationParams {
  pkce: string;
  state: string;
}

/**
 * Session storage interface class.
 */
export abstract class SessionStorage {
  abstract getSession(): Session | undefined;
  abstract setSession(session: Session | undefined): void;
  abstract setOauthVerificationParams(oAuthParams: OAuthVerificationParams): void;
  abstract getOauthVerificationParams(): OAuthVerificationParams | undefined;
}
