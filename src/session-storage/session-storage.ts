import { CognitoClient, Session } from "../cognito-client.js";

export abstract class ISessionStorage {
  constructor(protected client: CognitoClient) {}

  protected async refreshSession(session: Session) {
    if (session && new Date().getTime() >= session.expiresIn) {
      try {
        return this.client.refreshSession(session.refreshToken);
      } catch (error) {
        return undefined;
      }
    }
    return session;
  }

  abstract getSession(): Promise<Session | undefined>;
  abstract setSession(session: Session | undefined): void;
}
