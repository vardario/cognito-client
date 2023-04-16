import addSeconds from 'date-fns/addSeconds';
import { sha256 } from 'hash.js';
import { BigInteger } from 'jsbn';
import randomBytes from 'randombytes';

import { AuthError, AuthException, CognitoAuthErrorResponse, getAuthError } from './error';
import { SessionStorage } from './session-storage';

import {
  calculateSignature,
  calculateU,
  decodeJwt,
  generateA,
  generateSmallA,
  getPasswordAuthenticationKey,
} from './utils';

export interface UserAttribute {
  Name: string;
  Value: string;
}

/**
 * Cognito related OAuth props.
 */
export interface OAuth2Props {
  /**
   * Cognito domain for OAuth2 token endpoints.
   */
  cognitoDomain: string;

  /**
   * Requested OAuth scopes
   * @example ['email', 'openid']
   */
  scopes: string[];

  /**
   * Redirect URL after a successful OAuth2 authentication.
   */
  redirectUrl: string;

  /**
   * Response type.
   */
  responseType: 'code';
}

export interface CognitoClientProps {
  /**
   * Cognito User Pool ID
   * @example eu-central-1_lv6wixN9f
   */
  userPoolId: string;

  /**
   * Cognito User Pool Client ID
   */
  userPoolClientId: string;

  /**
   * Optional Cognito endpoint. Useful for local testing.
   * If not defined the endpoint will be determined by @see userPoolId .
   */
  endpoint?: string;

  /**
   * Session storage.
   * You can either choose on of the provided build in session
   * storages. Or provider your own one based on @see SessionStorage .
   *
   * <ul>
   *  <li>
   *    @see CookieSessionStorage
   *  </li>
   *  <li>
   *    @see MemorySessionStorage
   *  </li>
   * </ul>
   */
  sessionStorage: SessionStorage;

  /**
   * Cognito OAuth related options. See @see OAuthProps .
   */
  oAuth2?: OAuth2Props;
}

/**
 * Cognito User Session
 */
export interface Session {
  /**
   * JWT Access Token
   */
  accessToken: string;

  /**
   * JWT ID Token
   */
  idToken: string;

  /**
   * JWT refresh token
   */
  refreshToken: string;

  /**
   * Validity of the session in time stamp as milliseconds.
   */
  expiresIn: number;
}

/**
 * Represents the decoded values from a JWT ID token.
 */
export interface IdToken extends Record<string, string | string[] | number | boolean> {
  'cognito:username': string;
  'cognito:groups': string[];
  email_verified: boolean;
  email: string;
  iss: string;
  origin_jti: string;
  aud: string;
  event_id: string;
  token_use: 'id';
  auth_time: number;
  exp: number;
  iat: number;
  jti: string;
  sub: string;
}

export interface AccessToken extends Record<string, string | string[] | number | boolean> {
  auth_time: number;
  client_id: string;
  event_id: string;
  exp: number;
  iat: number;
  iss: string;
  jti: string;
  origin_jti: string;
  scope: string;
  sub: string;
  token_use: 'access';
  username: string;
}

export interface DecodedTokens {
  idToken: IdToken;
  accessToken: AccessToken;
}

/**
 * List of used and supported Cognito API calls.
 * @see https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_Operations.html for more details
 */
export enum CognitoServiceTarget {
  InitiateAuth = 'InitiateAuth',
  RespondToAuthChallenge = 'RespondToAuthChallenge',
  SignUp = 'SignUp',
  ConfirmSignUp = 'ConfirmSignUp',
  ChangePassword = 'ChangePassword',
  RevokeToken = 'RevokeToken',
  ForgotPassword = 'ForgotPassword',
  ConfirmForgotPassword = 'ConfirmForgotPassword',
  ResendConfirmationCode = 'ResendConfirmationCode',
  UpdateUserAttributes = 'UpdateUserAttributes',
  VerifyUserAttribute = 'VerifyUserAttribute',
}

/**
 * Cognito supported federated identities public providers.
 * @see https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-identity.html for more information.
 */
export enum CognitoIdentityProvider {
  Cognito = 'COGNITO',
  Google = 'Google',
  Facebook = 'Facebook',
  Amazon = 'LoginWithAmazon',
  Apple = 'SignInWithApple',
}

export interface AuthenticationResult {
  AccessToken: string;
  ExpiresIn: number;
  IdToken: string;
  TokenType: string;
  RefreshToken: string;
}

export interface AuthenticationResponse {
  AuthenticationResult: AuthenticationResult;
}

export interface ChallengeResponse {
  ChallengeName: 'PASSWORD_VERIFIER';
  ChallengeParameters: {
    SALT: string;
    SECRET_BLOCK: string;
    SRP_B: string;
    USERNAME: string;
    USER_ID_FOR_SRP: string;
  };
}

/**
 * Lightweight AWS Cogito client without any AWS SDK dependencies.
 */
export class CognitoClient {
  private readonly cognitoEndpoint: string;
  private readonly cognitoPoolName: string;
  private readonly userPoolClientId: string;
  private readonly sessionStorage: SessionStorage;
  private readonly oAuth?: OAuth2Props;

  constructor({ userPoolId, userPoolClientId, endpoint, sessionStorage, oAuth2: oAuth }: CognitoClientProps) {
    const [cognitoPoolRegion, cognitoPoolName] = userPoolId.split('_');
    this.cognitoEndpoint = (endpoint || `https://cognito-idp.${cognitoPoolRegion}.amazonaws.com`).replace(/\/$/, '');
    this.cognitoPoolName = cognitoPoolName;
    this.userPoolClientId = userPoolClientId;
    this.sessionStorage = sessionStorage;
    this.oAuth = oAuth;
  }

  static getDecodedTokenFromSession(session: Session): DecodedTokens {
    const { payload: idToken } = decodeJwt<IdToken>(session.idToken);
    const { payload: accessToken } = decodeJwt<AccessToken>(session.accessToken);
    return {
      idToken,
      accessToken,
    };
  }

  private async cognitoRequest(body: object, serviceTarget: CognitoServiceTarget) {
    const respondToAuthChallenge = await fetch(this.cognitoEndpoint, {
      headers: {
        'x-amz-target': `AWSCognitoIdentityProviderService.${serviceTarget}`,
        'content-type': 'application/x-amz-json-1.1',
      },
      method: 'POST',
      body: JSON.stringify(body),
    });

    if (respondToAuthChallenge.status < 200 || respondToAuthChallenge.status > 299) {
      const errorMessage = (await respondToAuthChallenge.json()) as CognitoAuthErrorResponse;
      throw getAuthError(errorMessage);
    }

    return respondToAuthChallenge.json();
  }

  private static authResultToSession(authenticationResult: AuthenticationResult): Session {
    return {
      accessToken: authenticationResult.AccessToken,
      idToken: authenticationResult.IdToken,
      expiresIn: addSeconds(new Date(), authenticationResult.ExpiresIn).getTime(),
      refreshToken: authenticationResult.RefreshToken,
    };
  }

  /**
   *
   * Performs user authentication with username and password through ALLOW_USER_SRP_AUTH .
   * @see https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-authentication-flow.html for more details
   *
   * @param username Username
   * @param password Password
   * @throws {AuthException}
   */
  async authenticateUserSrp(username: string, password: string): Promise<Session> {
    const smallA = generateSmallA();
    const A = generateA(smallA);

    const initiateAuthPayload = {
      AuthFlow: 'USER_SRP_AUTH',
      ClientId: this.userPoolClientId,
      AuthParameters: {
        USERNAME: username,
        SRP_A: A.toString(16),
      },
      ClientMetadata: {},
    };

    const challenge = (await this.cognitoRequest(
      initiateAuthPayload,
      CognitoServiceTarget.InitiateAuth
    )) as ChallengeResponse;

    const B = new BigInteger(challenge.ChallengeParameters.SRP_B, 16);
    const salt = new BigInteger(challenge.ChallengeParameters.SALT, 16);
    const U = calculateU(A, B);

    const hkdf = getPasswordAuthenticationKey(
      this.cognitoPoolName,
      challenge.ChallengeParameters.USER_ID_FOR_SRP,
      password,
      B,
      U,
      smallA,
      salt
    );

    const { signature, timeStamp } = calculateSignature(
      this.cognitoPoolName,
      challenge.ChallengeParameters.USER_ID_FOR_SRP,
      challenge.ChallengeParameters.SECRET_BLOCK,
      hkdf
    );

    const respondToAuthChallengePayload = {
      ChallengeName: 'PASSWORD_VERIFIER',
      ClientId: this.userPoolClientId,
      ChallengeResponses: {
        PASSWORD_CLAIM_SECRET_BLOCK: challenge.ChallengeParameters.SECRET_BLOCK,
        PASSWORD_CLAIM_SIGNATURE: signature,
        USERNAME: challenge.ChallengeParameters.USER_ID_FOR_SRP,
        TIMESTAMP: timeStamp,
      },
      ClientMetadata: {},
    };

    const { AuthenticationResult } = await this.cognitoRequest(
      respondToAuthChallengePayload,
      CognitoServiceTarget.RespondToAuthChallenge
    );

    const session = CognitoClient.authResultToSession(AuthenticationResult);
    this.sessionStorage.setSession(session);

    return session;
  }

  /**
   *
   * Performs user authentication with username and password through USER_PASSWORD_AUTH .
   * @see https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-authentication-flow.html for more details
   *
   * @param username Username
   * @param password Password
   * @throws {AuthException}
   */
  async authenticateUser(username: string, password: string): Promise<Session> {
    const initiateAuthPayload = {
      AuthFlow: 'USER_PASSWORD_AUTH',
      ClientId: this.userPoolClientId,
      AuthParameters: {
        USERNAME: username,
        PASSWORD: password,
      },
      ClientMetadata: {},
    };

    const { AuthenticationResult } = (await this.cognitoRequest(
      initiateAuthPayload,
      CognitoServiceTarget.InitiateAuth
    )) as AuthenticationResponse;

    const session = CognitoClient.authResultToSession(AuthenticationResult);
    this.sessionStorage.setSession(session);

    return session;
  }

  private async refreshSession(session: Session): Promise<Session | undefined> {
    const refreshTokenPayload = {
      AuthFlow: 'REFRESH_TOKEN_AUTH',
      ClientId: this.userPoolClientId,
      AuthParameters: {
        REFRESH_TOKEN: session.refreshToken,
      },
      ClientMetadata: {},
    };

    const { AuthenticationResult } = (await this.cognitoRequest(
      refreshTokenPayload,
      CognitoServiceTarget.InitiateAuth
    )) as AuthenticationResponse;

    const newSession = CognitoClient.authResultToSession({
      ...AuthenticationResult,
      RefreshToken: session.refreshToken,
    });

    this.sessionStorage.setSession(newSession);

    return newSession;
  }

  /**
   * Returns the current auth session.
   * The auth session is only defined when we previously had a successful user authentication.
   * This function will also take care to refresh the session with the refresh token in case
   * the current session has expired.
   *
   * @throws {AuthException}
   */
  async getSession(): Promise<Session | undefined> {
    const session = this.sessionStorage.getSession();
    if (session) {
      if (new Date().getTime() >= session.expiresIn) {
        return this.refreshSession(session);
      }
    }
    return session;
  }

  /**
   *
   * @param username Username
   * @param password Password
   *
   * @throws {AuthException}
   */
  async signUp(username: string, password: string, userAttributes?: UserAttribute[]) {
    const signUpPayload = {
      ClientId: this.userPoolClientId,
      Username: username,
      Password: password,
      UserAttributes: userAttributes,
    };

    const data = await this.cognitoRequest(signUpPayload, CognitoServiceTarget.SignUp);

    return {
      id: data.UserSub as string,
      confirmed: data.UserConfirmed as boolean,
    };
  }

  /**
   * Confirms the user registration via verification code.
   *
   * @param username Username
   * @param code Confirmation code the user gets through the registration E-Mail
   *
   * @throws {AuthException}
   */
  async confirmSignUp(username: string, code: string) {
    const confirmSignUpPayload = {
      ClientId: this.userPoolClientId,
      ConfirmationCode: code,
      Username: username,
    };

    const result = await this.cognitoRequest(confirmSignUpPayload, CognitoServiceTarget.ConfirmSignUp);
  }

  /**
   *
   * @param currentPassword Current user password.
   * @param newPassword  New user password.
   *
   * @throws {AuthException}
   */
  async changePassword(currentPassword: string, newPassword: string) {
    const session = await this.getSession();

    if (session === undefined) {
      throw new AuthException('User must be authenticated', AuthError.UserNotAuthenticated);
    }

    const changePasswordPayload = {
      PreviousPassword: currentPassword,
      ProposedPassword: newPassword,
      AccessToken: session.accessToken,
    };

    const result = await this.cognitoRequest(changePasswordPayload, CognitoServiceTarget.ChangePassword);
  }

  async updateUserAttributes(userAttributes: UserAttribute[]) {
    const session = await this.getSession();

    if (session === undefined) {
      throw new AuthException('User must be authenticated', AuthError.UserNotAuthenticated);
    }

    const updateUserAttributesPayload = {
      UserAttributes: userAttributes,
      AccessToken: session.accessToken,
    };

    const result = await this.cognitoRequest(updateUserAttributesPayload, CognitoServiceTarget.UpdateUserAttributes);
  }

  async verifyUserAttribute(attributeName: string, code: string) {
    const session = await this.getSession();

    if (session === undefined) {
      throw new AuthException('User must be authenticated', AuthError.UserNotAuthenticated);
    }

    const verifyUserAttributePayload = {
      AttributeName: attributeName,
      Code: code,
      AccessToken: session.accessToken,
    };

    const result = await this.cognitoRequest(verifyUserAttributePayload, CognitoServiceTarget.VerifyUserAttribute);
  }

  /**
   * Sign out the user and remove the current user session.
   *
   * @throws {AuthException}
   */
  async signOut() {
    const session = await this.getSession();
    if (session === undefined) {
      throw new AuthException('User must be authenticated', AuthError.UserNotAuthenticated);
    }

    const revokeTokenPayload = {
      Token: session.refreshToken,
      ClientId: this.userPoolClientId,
    };

    this.sessionStorage.setSession(undefined);
    await this.cognitoRequest(revokeTokenPayload, CognitoServiceTarget.RevokeToken);
  }

  /**
   * Request forgot password.
   * @param username Username
   *
   * @throws {AuthException}
   */
  async forgotPassword(username: string) {
    const forgotPasswordPayload = {
      ClientId: this.userPoolClientId,
      Username: username,
    };

    await this.cognitoRequest(forgotPasswordPayload, CognitoServiceTarget.ForgotPassword);
  }

  /**
   * Confirms the new password via the given code send via cognito triggered by @see forgotPassword .
   *
   * @param username Username
   * @param newPassword New password
   * @param confirmationCode Confirmation code which the user got through E-mail
   *
   * @throws {AuthException}
   */
  async confirmForgotPassword(username: string, newPassword: string, confirmationCode: string) {
    const confirmForgotPasswordPayload = {
      ClientId: this.userPoolClientId,
      Username: username,
      ConfirmationCode: confirmationCode,
      Password: newPassword,
    };

    await this.cognitoRequest(confirmForgotPasswordPayload, CognitoServiceTarget.ConfirmForgotPassword);
  }

  /**
   * Triggers cognito to resend the confirmation code
   * @param username Username
   */
  async resendConfirmationCode(username: string) {
    const resendConfirmationCodePayLoad = {
      ClientId: this.userPoolClientId,
      Username: username,
    };

    await this.cognitoRequest(resendConfirmationCodePayLoad, CognitoServiceTarget.ResendConfirmationCode);
  }

  /**
   * Returns a link to Cognito`s Hosted UI for OAuth2 authentication.
   * This method works in conjunction with @see handleCodeFlow .
   *
   * @param identityProvider When provided, this will generate a link which
   * tells Cognito`s Hosted UI to redirect to the given federated identity provider.
   *
   * @throws {Error}
   */
  generateOAuthSignInUrl(identityProvider?: CognitoIdentityProvider) {
    if (this.oAuth === undefined) {
      throw Error('You have to define oAuth options to use generateFederatedSignUrl');
    }

    const state = randomBytes(32).toString('hex');
    const pkce = randomBytes(128).toString('hex');

    const code_challenge = Buffer.from(sha256().update(pkce).digest())
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');

    const queryParams = new URLSearchParams();

    queryParams.append('redirect_uri', this.oAuth.redirectUrl);
    queryParams.append('response_type', this.oAuth.responseType);
    queryParams.append('client_id', this.userPoolClientId);
    identityProvider && queryParams.append('identity_provider', identityProvider);
    queryParams.append('scope', this.oAuth.scopes.join(' '));
    queryParams.append('state', state);
    queryParams.append('code_challenge', code_challenge);
    queryParams.append('code_challenge_method', 'S256');

    this.sessionStorage.setOauthVerificationParams({
      state,
      pkce,
    });

    return `${this.oAuth.cognitoDomain}/oauth2/authorize?${queryParams.toString()}`;
  }

  /**
   *
   * Handles Cognito`s OAuth2 code flow after redirection from Cognito`s Hosted UI.
   * The method call assumes that @see generateOAuthSignInUrl was used to
   * generated the link to the Hosted UI.
   *
   * @param returnUrl The full return URL from redirection after a successful OAuth2
   * authentication.
   *
   * @throws {Error}
   */
  async handleCodeFlow(returnUrl: string): Promise<Session> {
    if (this.oAuth === undefined) {
      throw Error('You have to define oAuth options to use handleCodeFlow');
    }

    const url = new URL(returnUrl);
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');

    if (code === null || state === null) {
      throw Error('code or state parameter is missing from return url.');
    }

    const oAuthVerificationParams = this.sessionStorage.getOauthVerificationParams();

    if (oAuthVerificationParams === undefined) {
      throw new Error('OAuth verification parameters are missing, did you forgot to call generateOAuthSignInUrl ?');
    }

    if (oAuthVerificationParams.state !== state) {
      throw new Error(
        'state parameter does not match with previous value generated by previous call of generateOAuthSignInUrl .'
      );
    }

    const urlParams = new URLSearchParams();

    urlParams.append('grant_type', 'authorization_code');
    urlParams.append('code', code);
    urlParams.append('client_id', this.userPoolClientId);
    urlParams.append('redirect_uri', this.oAuth.redirectUrl);
    urlParams.append('code_verifier', oAuthVerificationParams.pkce);

    const tokenEndpoint = `${this.oAuth.cognitoDomain}/oauth2/token`;

    const response = await fetch(tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: urlParams.toString(),
    });

    const { access_token, refresh_token, id_token, expires_in, token_type, error } = await response.json();

    if (error) {
      throw new Error(error);
    }

    const session = CognitoClient.authResultToSession({
      AccessToken: access_token,
      RefreshToken: refresh_token,
      IdToken: id_token,
      ExpiresIn: expires_in,
      TokenType: token_type,
    });

    this.sessionStorage.setSession(session);
    return session;
  }
}
