import { Session } from '../cognito-client.js';
import { OAuthVerificationParams, SessionStorage } from './session-storage.js';

/**
 * In-memory based session storage. Useful for testing.
 */
export class MemorySessionStorage extends SessionStorage {
  private session?: Session;
  private oAuthVerificationParams?: OAuthVerificationParams;

  getSession() {
    return this.session;
  }

  setSession(session: Session | undefined) {
    this.session = session;
  }

  getOauthVerificationParams(): OAuthVerificationParams | undefined {
    return this.oAuthVerificationParams;
  }

  setOauthVerificationParams(oAuthParams: OAuthVerificationParams): void {
    this.oAuthVerificationParams = oAuthParams;
  }
}
