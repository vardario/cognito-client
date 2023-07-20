import { Session } from "../cognito-client.js";
import { ISessionStorage } from "./session-storage.js";

export class MemorySessionStorage extends ISessionStorage {
  private session: Session | undefined;

  async getSession(): Promise<Session | undefined> {
    if (!this.session) {
      return undefined;
    }
    return this.refreshSession(this.session);
  }
  setSession(session: Session | undefined): void {
    this.session = session;
  }
}
