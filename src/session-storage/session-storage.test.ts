import { randomBytes } from 'crypto';
import { Session } from '../cognito-client';
import { setupJsDom } from '../test-utils';
import { CookieSessionStorage } from './cookie-session-storage';
import { LocalStorageSessionStorage } from './local-storage-session-storage';
import { MemorySessionStorage } from './memory-session-storage';
import { OAuthVerificationParams } from './session-storage';

setupJsDom();

const sessionStorages = [
  new MemorySessionStorage(),
  new LocalStorageSessionStorage({ storageName: 'session' }),
  new CookieSessionStorage({
    domain: 'localhost',
    cookieName: 'session',
  }),
];

const session: Session = {
  accessToken: randomBytes(128).toString('base64'),
  expiresIn: 600,
  idToken: randomBytes(128).toString('base64'),
  refreshToken: randomBytes(128).toString('base64'),
};

const oAuthVerificationParams: OAuthVerificationParams = {
  pkce: randomBytes(128).toString('base64'),
  state: randomBytes(128).toString('base64'),
};

test('SessionStorage', () => {
  sessionStorages.forEach((sessionStorage) => {
    sessionStorage.setSession(session);
    expect(sessionStorage.getSession()).toStrictEqual(session);

    sessionStorage.setOauthVerificationParams(oAuthVerificationParams);
    expect(sessionStorage.getOauthVerificationParams()).toStrictEqual(oAuthVerificationParams);
  });
});
