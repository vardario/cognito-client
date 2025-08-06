import {
  ChangePasswordException,
  ChangePasswordError,
  ConfirmForgotPasswordError,
  ConfirmSignUpError,
  ForgotPasswordError,
  GlobalSignOutError,
  InitAuthError,
  ResendConfirmationCodeError,
  RespondToAuthChallengeError,
  RevokeTokenError,
  SignUpError,
  UpdateUserAttributesError,
  VerifyUserAttributeError,
  ConfirmForgotPasswordException,
  ConfirmSignUpException,
  ForgotPasswordException,
  GlobalSignOutException,
  InitiateAuthException,
  ResendConfirmationException,
  RespondToAuthChallengeException,
  RevokeTokenException,
  SignUpException,
  UpdateUserAttributesException,
  VerifyUserAttributeException,
  COMMON_EXCEPTIONS,
  CommonError,
  CommonException,
  VerifySoftwareTokenError,
  VerifySoftwareTokenException,
  AssociateSoftwareTokenError,
  AssociateSoftwareTokenException,
  SetUserMFAPreferenceError,
  SetUserMFAPreferenceException,
  ListDevicesException,
  ListDevicesError,
  GetUserException,
  GetUserError
} from './error.js';

import {
  base64UrlToUint8Array,
  calculateSecretHash,
  calculateSignature,
  calculateU,
  decodeJwt,
  digest,
  generateA,
  generateSmallA,
  getPasswordAuthenticationKey,
  publicKeyCredentialToJSON,
  randomBytes,
  uint8ArrayFromString,
  uint8ArrayToBase64String
} from './utils.js';

export interface CognitoBaseRequest {
  ClientId: string;
  ClientMetadata?: Record<string, string>;
  AnalyticsMetadata?: {
    AnalyticsEndpointId: string;
  };
  UserContextData?: {
    EncodedData?: string;
    IpAddress?: string;
  };
}

export interface _InitiateAuthUserSrpAuthRequest extends CognitoBaseRequest {
  AuthFlow: 'USER_SRP_AUTH';
  AuthParameters: {
    USERNAME: string;
    SRP_A: string;
    SECRET_HASH?: string;
  };
}

export interface _InitiateAuthUserPasswordAuthRequest extends CognitoBaseRequest {
  AuthFlow: 'USER_PASSWORD_AUTH';
  AuthParameters: {
    USERNAME: string;
    PASSWORD: string;
    SECRET_HASH?: string;
  };
}

export interface _InitiateAuthRefreshTokenAuthRequest extends CognitoBaseRequest {
  AuthFlow: 'REFRESH_TOKEN_AUTH';
  AuthParameters: {
    REFRESH_TOKEN: string;
    SECRET_HASH?: string;
    USERNAME?: never;
  };
}

export interface _InitiateAuthCustomAuthRequest extends CognitoBaseRequest {
  AuthFlow: 'CUSTOM_AUTH';
  AuthParameters: {
    USERNAME: string;
    SECRET_HASH?: string;
  };
}

export interface _InitiateAuthUserAuthRequest extends CognitoBaseRequest {
  AuthFlow: 'USER_AUTH';
  AuthParameters: {
    USERNAME: string;
    PREFERRED_CHALLENGE?: AuthChallenge;
    SECRET_HASH?: string;
  };
}

type _InitiateAuthRequest =
  | _InitiateAuthUserSrpAuthRequest
  | _InitiateAuthUserPasswordAuthRequest
  | _InitiateAuthRefreshTokenAuthRequest
  | _InitiateAuthCustomAuthRequest
  | _InitiateAuthUserAuthRequest;

export type InitiateAuthRequest =
  | Omit<_InitiateAuthUserSrpAuthRequest, 'ClientId'>
  | Omit<_InitiateAuthUserPasswordAuthRequest, 'ClientId'>
  | Omit<_InitiateAuthRefreshTokenAuthRequest, 'ClientId'>
  | Omit<_InitiateAuthCustomAuthRequest, 'ClientId'>
  | Omit<_InitiateAuthUserAuthRequest, 'ClientId'>;

export interface RespondToAuthChallengeBaseRequest extends CognitoBaseRequest {
  Session?: string;
}

export interface _RespondToAuthChallengePasswordVerifierRequest extends RespondToAuthChallengeBaseRequest {
  ChallengeName: 'PASSWORD_VERIFIER';
  ChallengeResponses: {
    USERNAME: string;
    PASSWORD_CLAIM_SECRET_BLOCK: string;
    PASSWORD_CLAIM_SIGNATURE: string;
    TIMESTAMP: string;
    SECRET_HASH?: string;
  };
}

export interface _RespondToAuthChallengeSmsMfaRequest extends RespondToAuthChallengeBaseRequest {
  ChallengeName: 'SMS_MFA';
  ChallengeResponses: {
    USERNAME: string;
    SMS_MFA_CODE: string;
    SECRET_HASH?: string;
  };
}

export interface _RespondToAuthChallengeCustomChallengeNameRequest extends RespondToAuthChallengeBaseRequest {
  ChallengeName: 'CUSTOM_CHALLENGE';
  ChallengeResponses: {
    USERNAME: string;
    ANSWER: string;
    SECRET_HASH?: string;
  };
}

export interface _RespondToAuthChallengeNewPasswordRequiredRequest extends RespondToAuthChallengeBaseRequest {
  ChallengeName: 'NEW_PASSWORD_REQUIRED';
  ChallengeResponses: {
    USERNAME: string;
    NEW_PASSWORD: string;
    SECRET_HASH?: string;
  };
}

export interface _RespondToAuthChallengeSoftwareTokenMfaRequest extends RespondToAuthChallengeBaseRequest {
  ChallengeName: 'SOFTWARE_TOKEN_MFA';
  ChallengeResponses: {
    USERNAME: string;
    SOFTWARE_TOKEN_MFA_CODE: string;
    SECRET_HASH?: string;
  };
}

export interface _RespondToAuthChallengeDeviceSrpAuthRequest extends RespondToAuthChallengeBaseRequest {
  ChallengeName: 'DEVICE_SRP_AUTH';
  ChallengeResponses: {
    USERNAME: string;
    SRP_A: string;
    SECRET_HASH?: string;
  };
}

export interface _RespondToAuthChallengeDevicePasswordVerifierRequest extends RespondToAuthChallengeBaseRequest {
  ChallengeName: 'DEVICE_PASSWORD_VERIFIER';
  ChallengeResponses: {
    USERNAME: string;
    PASSWORD_CLAIM_SECRET_BLOCK: string;
    PASSWORD_CLAIM_SIGNATURE: string;
    TIMESTAMP: string;
    DEVICE_KEY: string;
    SECRET_HASH?: string;
  };
}

export interface _RespondToAuthChallengeMfaSetupRequest extends RespondToAuthChallengeBaseRequest {
  ChallengeName: 'MFA_SETUP';
  ChallengeResponses: {
    USERNAME: string;
    SMS_MFA_CODE?: string;
    SOFTWARE_TOKEN_MFA_CODE?: string;
    SECRET_HASH?: string;
  };
  Session?: never;
}

export interface _RespondToAuthChallengeSelectMfaTypeRequest extends RespondToAuthChallengeBaseRequest {
  ChallengeName: 'SELECT_MFA_TYPE';
  ChallengeResponses: {
    USERNAME: string;
    SOFTWARE_TOKEN_MFA_CODE?: string;
    SECRET_HASH?: string;
  };
}

export interface _RespondToAuthChallengeWebAuthnRequest extends RespondToAuthChallengeBaseRequest {
  ChallengeName: 'WEB_AUTHN';
  ChallengeResponses: {
    USERNAME: string;
    CREDENTIAL: any; // PublicKeyCredentialJSON
    SECRET_HASH?: string;
  };
}

type _RespondToAuthChallengeRequest =
  | _RespondToAuthChallengePasswordVerifierRequest
  | _RespondToAuthChallengeSmsMfaRequest
  | _RespondToAuthChallengeCustomChallengeNameRequest
  | _RespondToAuthChallengeNewPasswordRequiredRequest
  | _RespondToAuthChallengeSoftwareTokenMfaRequest
  | _RespondToAuthChallengeDeviceSrpAuthRequest
  | _RespondToAuthChallengeDevicePasswordVerifierRequest
  | _RespondToAuthChallengeMfaSetupRequest
  | _RespondToAuthChallengeSelectMfaTypeRequest
  | _RespondToAuthChallengeWebAuthnRequest;

export type RespondToAuthChallengeRequest =
  | Omit<_RespondToAuthChallengePasswordVerifierRequest, 'ClientId'>
  | Omit<_RespondToAuthChallengeSmsMfaRequest, 'ClientId'>
  | Omit<_RespondToAuthChallengeCustomChallengeNameRequest, 'ClientId'>
  | Omit<_RespondToAuthChallengeNewPasswordRequiredRequest, 'ClientId'>
  | Omit<_RespondToAuthChallengeSoftwareTokenMfaRequest, 'ClientId'>
  | Omit<_RespondToAuthChallengeDeviceSrpAuthRequest, 'ClientId'>
  | Omit<_RespondToAuthChallengeDevicePasswordVerifierRequest, 'ClientId'>
  | Omit<_RespondToAuthChallengeMfaSetupRequest, 'ClientId'>
  | Omit<_RespondToAuthChallengeSelectMfaTypeRequest, 'ClientId'>
  | Omit<_RespondToAuthChallengeWebAuthnRequest, 'ClientId'>;

export interface UserAttribute {
  Name: string;
  Value: string;
}

export interface ConfirmForgotPasswordRequest extends CognitoBaseRequest {
  ConfirmationCode: string;
  Password: string;
  Username: string;
  SecretHash?: string;
}

export interface ConfirmSignUpRequest extends CognitoBaseRequest {
  ConfirmationCode: string;
  Username: string;
  SecretHash?: string;
  ForceAliasCreation?: boolean;
}

export interface ForgotPasswordRequest extends CognitoBaseRequest {
  Username: string;
  SecretHash?: string;
}

export interface SignUpRequest extends CognitoBaseRequest {
  Username: string;
  Password: string;
  SecretHash?: string;
  UserAttributes?: UserAttribute[];
  ValidationData?: UserAttribute[];
}

export interface ResendConfirmationCodeRequest extends CognitoBaseRequest {
  Username: string;
  SecretHash?: string;
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
   * Cognito OAuth related options. See @see OAuthProps .
   */
  oAuth2?: OAuth2Props;

  /**
   * Optional Cognito User Pool Client Secret.
   */
  clientSecret?: string;
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
export enum ServiceTarget {
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
  GlobalSignOut = 'GlobalSignOut',
  GetUser = 'GetUser',
  AssociateSoftwareToken = 'AssociateSoftwareToken',
  VerifySoftwareToken = 'VerifySoftwareToken',
  ListDevices = 'ListDevices',
  SetUserMFAPreference = 'SetUserMFAPreference',
  StartWebAuthnRegistration = 'StartWebAuthnRegistration',
  CompleteWebAuthnRegistration = 'CompleteWebAuthnRegistration',
  DeleteWebAuthnCredential = 'DeleteWebAuthnCredential',
  ListWebAuthnCredentials = 'ListWebAuthnCredentials'
}

export interface AssociateSoftwareTokenRequest {
  AccessToken?: string;
  Session?: string;
}
export interface AssociateSoftwareResponse {
  SecretCode: string;
  Session: string;
}

export interface VerifySoftwareTokenRequest {
  AccessToken?: string;
  FriendlyDeviceName?: string;
  Session?: string;
  UserCode: string;
}
export interface VerifySoftwareTokenResponse {
  Session: string;
  Status: 'SUCCESS' | 'ERROR';
}

export interface ListDevicesRequest {
  AccessToken: string;
  Limit: number;
  PaginationToken?: 'string';
}

export interface Device {
  DeviceAttributes: [
    {
      Name: string;
      Value: string;
    }
  ];
  DeviceCreateDate: number;
  DeviceKey: string;
  DeviceLastAuthenticatedDate: number;
  DeviceLastModifiedDate: number;
}
export interface ListDevicesResponse {
  Devices: Device[];
  PaginationToken?: string;
}

/**
 * Cognito supported federated identities public providers.
 * @see https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-identity.html for more information.
 */
export enum IdentityProvider {
  Cognito = 'COGNITO',
  Google = 'Google',
  Facebook = 'Facebook',
  Amazon = 'LoginWithAmazon',
  Apple = 'SignInWithApple'
}

export interface AuthenticationResult {
  AccessToken: string;
  ExpiresIn: number;
  IdToken: string;
  RefreshToken: string;
  NewDeviceMetadata?: NewDeviceMetadata;
}

export interface NewDeviceMetadata {
  DeviceKey?: string;
  DeviceGroupKey?: string;
}

export type AuthChallenge = InitiateAuthChallengeResponse['ChallengeName'];

export interface InitiateAuthBaseResponse {
  AvailableChallenges: [];
  Session: string;
}

export interface InitiateAuthAuthenticationResponse extends InitiateAuthBaseResponse {
  AuthenticationResult: AuthenticationResult;
  ChallengeName?: never;
}

export interface InitiateAuthPasswordVerifierChallengeResponse extends InitiateAuthBaseResponse {
  AuthenticationResult?: never;
  ChallengeName: 'PASSWORD_VERIFIER';
  ChallengeParameters: {
    SALT: string;
    SECRET_BLOCK: string;
    SRP_B: string;
    USERNAME: string;
    USER_ID_FOR_SRP: string;
  };
}

export interface InitiateAuthSoftwareTokenMfaChallengeResponse extends InitiateAuthBaseResponse {
  AuthenticationResult?: never;
  ChallengeName: 'SOFTWARE_TOKEN_MFA';
}

export interface InitiateAuthWebAuthResponse extends InitiateAuthBaseResponse {
  AuthenticationResult?: never;
  ChallengeName: 'WEB_AUTHN';
  Session: string;
  ChallengeParameters: {
    CREDENTIAL_REQUEST_OPTIONS: string;
  };
}

export interface InitiateEmailOtpChallengeResponse extends InitiateAuthBaseResponse {
  AuthenticationResult?: never;
  ChallengeName: 'EMAIL_OTP';
  ChallengeParameters: {
    CODE_DELIVERY_DELIVERY_MEDIUM: string;
    CODE_DELIVERY_DESTINATION: string;
  };
  Session: string;
}

export interface InitAuthSelectChallengeResponse extends InitiateAuthBaseResponse {
  AuthenticationResult?: never;
  ChallengeName: 'SELECT_CHALLENGE';
  ChallengeParameters: never;
}

export interface InitAuthPasswordChallengeResponse extends InitiateAuthBaseResponse {
  AuthenticationResult?: never;
  ChallengeName: 'PASSWORD';
  ChallengeParameters: never;
}

export interface InitAuthPasswordSRPChallengeResponse extends InitiateAuthBaseResponse {
  AuthenticationResult?: never;
  ChallengeName: 'PASSWORD_SRP';
  ChallengeParameters: never;
}

export interface MfaOption {
  DeliveryMedium: 'SMS' | 'EMAIL';
  AttributeName: string;
}
export interface GetUserResponse {
  UserAttributes: UserAttribute[];
  Username: string;
  UserMFASettingList?: string[];
  MFAOptions?: MfaOption[];
  PreferredMfaSetting: string;
}

export interface SetUserMFAPreferenceRequest {
  AccessToken: string;
  EmailMfaSettings?: {
    Enabled?: boolean;
    PreferredMfa?: boolean;
  };
  SMSMfaSettings?: {
    Enabled?: boolean;
    PreferredMfa?: boolean;
  };
  SoftwareTokenMfaSettings?: {
    Enabled?: boolean;
    PreferredMfa?: boolean;
  };
}

export interface StartWebAuthnRegistrationRequest {
  AccessToken: string;
}

export interface StartWebAuthnRegistrationResponse {
  CredentialCreationOptions: PublicKeyCredentialCreationOptions;
}

export interface CompleteWebAuthnRegistrationRequest {
  AccessToken: string;
  Credential: PublicKeyCredential;
}

export interface DeleteWebAuthnCredentialRequest {
  AccessToken: string;
  CredentialId: string;
}

export interface ListWebAuthnCredentialsRequest {
  AccessToken: string;
  MaxResults?: number;
  NextToken?: string;
}

export interface WebAuthnCredential {
  AuthenticatorTransports: string[];
  CreatedAt: string;
  CredentialId: string;
  FriendlyCredentialName: string;
  RelyingPartyId: string;
  AuthenticatorAttachment?: string;
}

export interface ListWebAuthnCredentialsResponse {
  Credentials: WebAuthnCredential[];
  NextToken?: string;
}

export type InitiateAuthChallengeResponse =
  | InitiateAuthPasswordVerifierChallengeResponse
  | InitiateAuthSoftwareTokenMfaChallengeResponse
  | InitiateAuthWebAuthResponse
  | InitiateEmailOtpChallengeResponse
  | InitAuthSelectChallengeResponse
  | InitAuthPasswordChallengeResponse
  | InitAuthPasswordSRPChallengeResponse;

export type InitiateAuthResponse =
  | InitiateAuthAuthenticationResponse
  | InitiateAuthPasswordVerifierChallengeResponse
  | InitiateAuthChallengeResponse;

type CognitoResponseMap = {
  [ServiceTarget.InitiateAuth]: InitiateAuthResponse;
  [ServiceTarget.RespondToAuthChallenge]: InitiateAuthResponse;
  [ServiceTarget.SignUp]: { UserConfirmed: boolean; UserSub: string };
  [ServiceTarget.ConfirmSignUp]: void;
  [ServiceTarget.ChangePassword]: void;
  [ServiceTarget.RevokeToken]: void;
  [ServiceTarget.ForgotPassword]: void;
  [ServiceTarget.ConfirmForgotPassword]: void;
  [ServiceTarget.ResendConfirmationCode]: void;
  [ServiceTarget.UpdateUserAttributes]: void;
  [ServiceTarget.VerifyUserAttribute]: void;
  [ServiceTarget.GlobalSignOut]: void;
  [ServiceTarget.GetUser]: GetUserResponse;
  [ServiceTarget.AssociateSoftwareToken]: AssociateSoftwareResponse;
  [ServiceTarget.VerifySoftwareToken]: VerifySoftwareTokenResponse;
  [ServiceTarget.ListDevices]: ListDevicesResponse;
  [ServiceTarget.SetUserMFAPreference]: void;
  [ServiceTarget.StartWebAuthnRegistration]: StartWebAuthnRegistrationResponse;
  [ServiceTarget.CompleteWebAuthnRegistration]: void;
  [ServiceTarget.DeleteWebAuthnCredential]: void;
  [ServiceTarget.ListWebAuthnCredentials]: ListWebAuthnCredentialsResponse;
};

type CognitoRequestMap = {
  [ServiceTarget.InitiateAuth]: _InitiateAuthRequest;
  [ServiceTarget.RespondToAuthChallenge]: _RespondToAuthChallengeRequest;
  [ServiceTarget.SignUp]: SignUpRequest;
  [ServiceTarget.ConfirmSignUp]: ConfirmSignUpRequest;
  [ServiceTarget.ChangePassword]: {
    PreviousPassword: string;
    ProposedPassword: string;
    AccessToken: string;
  };
  [ServiceTarget.RevokeToken]: {
    Token: string;
    ClientId: string;
    ClientSecret?: string;
  };
  [ServiceTarget.ForgotPassword]: ForgotPasswordRequest;
  [ServiceTarget.ConfirmForgotPassword]: ConfirmForgotPasswordRequest;
  [ServiceTarget.ResendConfirmationCode]: ResendConfirmationCodeRequest;
  [ServiceTarget.UpdateUserAttributes]: {
    UserAttributes: UserAttribute[];
    AccessToken: string;
  };
  [ServiceTarget.VerifyUserAttribute]: {
    AttributeName: string;
    Code: string;
    AccessToken: string;
  };
  [ServiceTarget.GlobalSignOut]: {
    AccessToken: string;
  };
  [ServiceTarget.GetUser]: {
    AccessToken: string;
  };
  [ServiceTarget.AssociateSoftwareToken]: AssociateSoftwareTokenRequest;
  [ServiceTarget.VerifySoftwareToken]: VerifySoftwareTokenRequest;
  [ServiceTarget.ListDevices]: ListDevicesRequest;
  [ServiceTarget.SetUserMFAPreference]: SetUserMFAPreferenceRequest;
  [ServiceTarget.StartWebAuthnRegistration]: StartWebAuthnRegistrationRequest;
  [ServiceTarget.CompleteWebAuthnRegistration]: any;
  [ServiceTarget.DeleteWebAuthnCredential]: DeleteWebAuthnCredentialRequest;
  [ServiceTarget.ListWebAuthnCredentials]: ListWebAuthnCredentialsRequest;
};

export function adaptExpiresIn(auth: AuthenticationResult) {
  // Cognito returns expiresIn in seconds, but we want it in milliseconds from now
  return {
    ...auth,
    ExpiresIn: new Date().getTime() + auth.ExpiresIn * 1000
  };
}

export async function cognitoRequest<T extends ServiceTarget>(
  body: CognitoRequestMap[T],
  serviceTarget: T,
  cognitoEndpoint: string
): Promise<CognitoResponseMap[T]>;

export async function cognitoRequest(body: object, serviceTarget: ServiceTarget, cognitoEndpoint: string) {
  const cognitoResponse = await fetch(cognitoEndpoint, {
    headers: {
      'x-amz-target': `AWSCognitoIdentityProviderService.${serviceTarget}`,
      'content-type': 'application/x-amz-json-1.1'
    },
    method: 'POST',
    body: JSON.stringify(body)
  });

  if (cognitoResponse && cognitoResponse.status < 300) {
    return cognitoResponse.json();
  }

  const cognitoResponseBody = await cognitoResponse.json();

  /**
   * The whole error handling and value sanitization was inspired
   * by @see https://github.com/aws-amplify/amplify-js/blob/1f5eefd9c40285eb99e57764ac8fca1f9519e2c6/packages/core/src/clients/serde/json.ts#L14
   */

  const sanitizeErrorType = (rawValue: string | number): string => {
    const [cleanValue] = rawValue.toString().split(/[,:]+/);
    if (cleanValue.includes('#')) {
      return cleanValue.split('#')[1];
    }
    return cleanValue;
  };

  const errorMessage =
    cognitoResponse.headers.get('X-Amzn-ErrorMessage') ??
    cognitoResponseBody.message ??
    cognitoResponseBody.Message ??
    'Unknown error';

  const cognitoException = sanitizeErrorType(
    cognitoResponse.headers.get('X-Amzn-ErrorType') ??
      cognitoResponseBody.code ??
      cognitoResponseBody.__type ??
      'Unknown'
  );

  if (COMMON_EXCEPTIONS.includes(cognitoException as CommonException)) {
    throw new CommonError(errorMessage, cognitoException as CommonException);
  }

  switch (serviceTarget) {
    case ServiceTarget.InitiateAuth:
      throw new InitAuthError(errorMessage, cognitoException as InitiateAuthException);
    case ServiceTarget.RespondToAuthChallenge:
      throw new RespondToAuthChallengeError(errorMessage, cognitoException as RespondToAuthChallengeException);
    case ServiceTarget.SignUp:
      throw new SignUpError(errorMessage, cognitoException as SignUpException);
    case ServiceTarget.ConfirmSignUp:
      throw new ConfirmSignUpError(errorMessage, cognitoException as ConfirmSignUpException);
    case ServiceTarget.ChangePassword:
      throw new ChangePasswordError(errorMessage, cognitoException as ChangePasswordException);
    case ServiceTarget.RevokeToken:
      throw new RevokeTokenError(errorMessage, cognitoException as RevokeTokenException);
    case ServiceTarget.ForgotPassword:
      throw new ForgotPasswordError(errorMessage, cognitoException as ForgotPasswordException);
    case ServiceTarget.ConfirmForgotPassword:
      throw new ConfirmForgotPasswordError(errorMessage, cognitoException as ConfirmForgotPasswordException);
    case ServiceTarget.ResendConfirmationCode:
      throw new ResendConfirmationCodeError(errorMessage, cognitoException as ResendConfirmationException);
    case ServiceTarget.UpdateUserAttributes:
      throw new UpdateUserAttributesError(errorMessage, cognitoException as UpdateUserAttributesException);
    case ServiceTarget.VerifyUserAttribute:
      throw new VerifyUserAttributeError(errorMessage, cognitoException as VerifyUserAttributeException);
    case ServiceTarget.GlobalSignOut:
      throw new GlobalSignOutError(errorMessage, cognitoException as GlobalSignOutException);
    case ServiceTarget.AssociateSoftwareToken:
      throw new AssociateSoftwareTokenError(errorMessage, cognitoException as AssociateSoftwareTokenException);
    case ServiceTarget.VerifySoftwareToken:
      throw new VerifySoftwareTokenError(errorMessage, cognitoException as VerifySoftwareTokenException);
    case ServiceTarget.SetUserMFAPreference:
      throw new SetUserMFAPreferenceError(errorMessage, cognitoException as SetUserMFAPreferenceException);
    case ServiceTarget.ListDevices:
      throw new ListDevicesError(errorMessage, cognitoException as ListDevicesException);
    case ServiceTarget.GetUser:
      throw new GetUserError(errorMessage, cognitoException as GetUserException);
  }
}

/**
 * Lightweight AWS Cogito client without any AWS SDK dependencies.
 */
export class CognitoClient {
  private readonly cognitoEndpoint: string;
  private readonly cognitoPoolName: string;
  private readonly userPoolClientId: string;
  private readonly oAuth?: OAuth2Props;
  private readonly clientSecret?: string;

  constructor({ userPoolId, userPoolClientId, endpoint, oAuth2: oAuth, clientSecret }: CognitoClientProps) {
    const [cognitoPoolRegion, cognitoPoolName] = userPoolId.split('_');
    this.cognitoEndpoint = (endpoint || `https://cognito-idp.${cognitoPoolRegion}.amazonaws.com`).replace(/\/$/, '');
    this.cognitoPoolName = cognitoPoolName;
    this.userPoolClientId = userPoolClientId;
    this.oAuth = oAuth;
    this.clientSecret = clientSecret;
  }

  static getDecodedTokenFromSession(auth: AuthenticationResult): DecodedTokens {
    const { payload: idToken } = decodeJwt<IdToken>(auth.IdToken);
    const { payload: accessToken } = decodeJwt<AccessToken>(auth.AccessToken);
    return {
      idToken,
      accessToken
    };
  }

  async initiateAuth(request: InitiateAuthRequest): Promise<InitiateAuthResponse> {
    request.AuthParameters.SECRET_HASH =
      this.clientSecret && request.AuthParameters.USERNAME
        ? await calculateSecretHash(this.clientSecret, this.userPoolClientId, request.AuthParameters.USERNAME)
        : undefined;

    const cognitoResponse = await cognitoRequest(
      {
        ...request,
        ClientId: this.userPoolClientId
      },
      ServiceTarget.InitiateAuth,
      this.cognitoEndpoint
    );

    if (cognitoResponse.AuthenticationResult) {
      cognitoResponse.AuthenticationResult = adaptExpiresIn(cognitoResponse.AuthenticationResult);
    }

    return cognitoResponse;
  }

  /**
   *
   * Performs user authentication with username and password through ALLOW_USER_SRP_AUTH .
   * @see https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-authentication-flow.html for more details
   *
   * @param username Username
   * @param password Password
   *
   * @throws {InitAuthError, CognitoRespondToAuthChallengeError}
   */
  async authenticateUserSrp(username: string, password: string): Promise<InitiateAuthResponse> {
    const smallA = await generateSmallA();
    const A = generateA(smallA);

    const initUserSrpAuthResponse = await this.initiateAuth({
      AuthFlow: 'USER_SRP_AUTH',
      AuthParameters: {
        USERNAME: username,
        SRP_A: A.toString(16),
        SECRET_HASH:
          this.clientSecret && (await calculateSecretHash(this.clientSecret, this.userPoolClientId, username))
      },
      ClientMetadata: {}
    });

    if (initUserSrpAuthResponse.ChallengeName !== 'PASSWORD_VERIFIER') {
      return initUserSrpAuthResponse;
    }

    const B = BigInt('0x' + initUserSrpAuthResponse.ChallengeParameters.SRP_B);
    const salt = BigInt('0x' + initUserSrpAuthResponse.ChallengeParameters.SALT);
    const U = await calculateU(A, B);

    const hkdf = await getPasswordAuthenticationKey(
      this.cognitoPoolName,
      initUserSrpAuthResponse.ChallengeParameters.USER_ID_FOR_SRP,
      password,
      B,
      U,
      smallA,
      salt
    );

    const { signature, timeStamp } = await calculateSignature(
      this.cognitoPoolName,
      initUserSrpAuthResponse.ChallengeParameters.USER_ID_FOR_SRP,
      initUserSrpAuthResponse.ChallengeParameters.SECRET_BLOCK,
      hkdf
    );

    const passwordAuthChallengeResponse = await this.respondToAuthChallenge({
      ChallengeName: 'PASSWORD_VERIFIER',
      ChallengeResponses: {
        PASSWORD_CLAIM_SECRET_BLOCK: initUserSrpAuthResponse.ChallengeParameters.SECRET_BLOCK,
        PASSWORD_CLAIM_SIGNATURE: signature,
        USERNAME: initUserSrpAuthResponse.ChallengeParameters.USER_ID_FOR_SRP,
        TIMESTAMP: timeStamp,
        SECRET_HASH:
          this.clientSecret &&
          (await calculateSecretHash(
            this.clientSecret,
            this.userPoolClientId,
            initUserSrpAuthResponse.ChallengeParameters.USER_ID_FOR_SRP
          ))
      },
      ClientMetadata: {}
    });

    if (passwordAuthChallengeResponse.AuthenticationResult) {
      passwordAuthChallengeResponse.AuthenticationResult = adaptExpiresIn(
        passwordAuthChallengeResponse.AuthenticationResult
      );
    }

    return passwordAuthChallengeResponse;
  }

  /**
   *
   * Performs user authentication with username and password through USER_PASSWORD_AUTH .
   * @see https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-authentication-flow.html for more details
   *
   * @param username Username
   * @param password Password
   * @throws {InitAuthError}
   */
  async authenticateUser(username: string, password: string): Promise<InitiateAuthResponse> {
    const initiateAuthPayload: InitiateAuthRequest = {
      AuthFlow: 'USER_PASSWORD_AUTH',

      AuthParameters: {
        USERNAME: username,
        PASSWORD: password,
        SECRET_HASH:
          this.clientSecret && (await calculateSecretHash(this.clientSecret, this.userPoolClientId, username))
      },
      ClientMetadata: {}
    };

    const initUserPasswordAuthResponse = await this.initiateAuth(initiateAuthPayload);

    if (!initUserPasswordAuthResponse.AuthenticationResult) {
      return initUserPasswordAuthResponse;
    }

    return initUserPasswordAuthResponse;
  }

  /**
   * Initiates the authentication process for a user using a preferred challenge, such as WEB_AUTHN.
   */
  async authenticateWebAuthn(username: string) {
    const webAuthnPayload: InitiateAuthRequest = {
      AuthFlow: 'USER_AUTH',
      AuthParameters: {
        USERNAME: username,
        PREFERRED_CHALLENGE: 'WEB_AUTHN'
      }
    };

    const authResponse = await this.initiateAuth(webAuthnPayload);

    if (authResponse.ChallengeName !== 'WEB_AUTHN') {
      throw new InitAuthError(
        'Authentication failed, expected WEB_AUTHN challenge but received: ' + authResponse.ChallengeName,
        InitiateAuthException.InternalErrorException
      );
    }

    const credentialRequestOptions = JSON.parse(authResponse.ChallengeParameters.CREDENTIAL_REQUEST_OPTIONS);

    credentialRequestOptions.challenge = base64UrlToUint8Array(credentialRequestOptions.challenge);
    credentialRequestOptions.allowCredentials = (credentialRequestOptions.allowCredentials || []).map(
      (allowCred: any) => ({
        ...allowCred,
        id: base64UrlToUint8Array(allowCred.id)
      })
    );

    const credentials = await navigator.credentials.get({
      publicKey: credentialRequestOptions
    });

    const challengeResponse = await this.respondToAuthChallenge({
      ChallengeName: 'WEB_AUTHN',
      ChallengeResponses: {
        USERNAME: username,
        CREDENTIAL: JSON.stringify(publicKeyCredentialToJSON(credentials)),
        SECRET_HASH:
          this.clientSecret && (await calculateSecretHash(this.clientSecret, this.userPoolClientId, username))
      },
      Session: authResponse.Session
    });

    if (challengeResponse.AuthenticationResult) {
      challengeResponse.AuthenticationResult = adaptExpiresIn(challengeResponse.AuthenticationResult);
    }

    return challengeResponse;
  }

  /**
   * Registers a new WebAuthn device for the current user.
   * This method initiates the WebAuthn registration process by requesting the necessary options from Cognito,
   * then creates a new public key credential using the WebAuthn API, and finally
   * completes the registration by sending the credential back to Cognito.
   *
   * @param accessToken Access token of the current user.
   */
  async registerWebAuthnDevice(accessToken: string) {
    const { CredentialCreationOptions } = await cognitoRequest(
      {
        AccessToken: accessToken
      },
      ServiceTarget.StartWebAuthnRegistration,
      this.cognitoEndpoint
    );

    const credentials = await navigator.credentials.create({
      publicKey: CredentialCreationOptions
    });

    if (!(credentials instanceof PublicKeyCredential)) {
      throw new Error('Invalid credentials returned from WebAuthn API');
    }

    await this.completeWebAuthnRegistration({
      AccessToken: accessToken,
      Credential: credentials
    });
  }

  /**
   * Returns a new session based on the given refresh token.
   *
   * @param refreshToken  Refresh token from a previous session.
   * @param username Username is required when using a client secret and needs to be the cognito user id.
   * @returns @see Session
   * @throws {InitAuthError}
   */
  public async refreshSession(refreshToken: string, username?: string): Promise<AuthenticationResult> {
    const refreshTokenPayload: InitiateAuthRequest = {
      AuthFlow: 'REFRESH_TOKEN_AUTH',
      AuthParameters: {
        REFRESH_TOKEN: refreshToken,
        SECRET_HASH:
          this.clientSecret &&
          username &&
          (await calculateSecretHash(this.clientSecret, this.userPoolClientId, username))
      },
      ClientMetadata: {}
    };

    const { AuthenticationResult } = await this.initiateAuth(refreshTokenPayload);

    if (!AuthenticationResult) {
      throw new InitAuthError(
        'Authentication failed, no authentication result returned',
        InitiateAuthException.InternalErrorException
      );
    }

    if (!AuthenticationResult.RefreshToken) {
      AuthenticationResult.RefreshToken = refreshToken;
    }

    return AuthenticationResult;
  }

  /**
   *
   * @param username Username
   * @param password Password
   *
   * @throws {SignUpError}
   */
  async signUp(username: string, password: string, userAttributes?: UserAttribute[]) {
    const signUpRequest: SignUpRequest = {
      ClientId: this.userPoolClientId,
      Username: username,
      Password: password,
      UserAttributes: userAttributes,
      SecretHash: this.clientSecret && (await calculateSecretHash(this.clientSecret, this.userPoolClientId, username))
    };

    const data = await cognitoRequest(signUpRequest, ServiceTarget.SignUp, this.cognitoEndpoint);

    return {
      id: data.UserSub as string,
      confirmed: data.UserConfirmed as boolean
    };
  }

  /**
   * Confirms the user registration via verification code.
   *
   * @param username Username
   * @param code Confirmation code the user gets through the registration E-Mail
   *
   * @throws {ConfirmSignUpError}
   */
  async confirmSignUp(username: string, code: string) {
    const confirmSignUpRequest: ConfirmSignUpRequest = {
      ClientId: this.userPoolClientId,
      ConfirmationCode: code,
      Username: username,
      SecretHash: this.clientSecret && (await calculateSecretHash(this.clientSecret, this.userPoolClientId, username))
    };

    await cognitoRequest(confirmSignUpRequest, ServiceTarget.ConfirmSignUp, this.cognitoEndpoint);
  }

  /**
   *
   * @param currentPassword Current user password.
   * @param newPassword  New user password.
   *
   * @throws {ChangePasswordError}
   */
  async changePassword(currentPassword: string, newPassword: string, accessToken: string) {
    const changePasswordPayload = {
      PreviousPassword: currentPassword,
      ProposedPassword: newPassword,
      AccessToken: accessToken
    };

    await cognitoRequest(changePasswordPayload, ServiceTarget.ChangePassword, this.cognitoEndpoint);
  }

  /**
   * Gets the user information.
   * @param accessToken Access token of the current user.
   * @returns User information.
   */
  async getUser(accessToken: string): Promise<GetUserResponse> {
    const getUserPayload = {
      AccessToken: accessToken
    };

    return cognitoRequest(getUserPayload, ServiceTarget.GetUser, this.cognitoEndpoint);
  }

  /**
   * Associates a software token with the user.
   * @param params Request to associate a software token with the user.
   * @param params.AccessToken Access token of the current user.
   * @param params.Session Optional session identifier for the authentication process.
   * @param params.ClientMetadata Optional metadata to pass to the service.
   * @param params.UserContextData Optional user context data.
   * @param params.AnalyticsMetadata Optional analytics metadata.
   * @param params.FriendlyDeviceName Optional friendly name for the device.
   * @returns
   */
  async associateSoftwareToken(params: AssociateSoftwareTokenRequest): Promise<AssociateSoftwareResponse> {
    return cognitoRequest(params, ServiceTarget.AssociateSoftwareToken, this.cognitoEndpoint);
  }

  /**
   * Verifies a software token.
   * @param params Request to verify a software token.
   * @param params.AccessToken Access token of the current user.
   * @param params.FriendlyDeviceName Optional friendly name for the device.
   * @param params.Session Optional session identifier for the authentication process.
   * @param params.UserCode The user code to verify.
   * @returns
   */
  async verifySoftwareToken(params: VerifySoftwareTokenRequest): Promise<VerifySoftwareTokenResponse> {
    return cognitoRequest(params, ServiceTarget.VerifySoftwareToken, this.cognitoEndpoint);
  }

  /**
   * Responds to an authentication challenge.
   * @param params Request to respond to an authentication challenge.
   * @param params.ChallengeName Name of the challenge to respond to.
   * @param params.ChallengeResponses Responses to the challenge.
   * @param params.Session Session identifier for the authentication process.
   * @param params.ClientMetadata Optional metadata to pass to the service.
   * @param params.AccessToken Access token of the current user.
   * @param params.SecretHash Optional secret hash for the user pool client.
   * @returns
   */
  async respondToAuthChallenge(params: RespondToAuthChallengeRequest): Promise<InitiateAuthResponse> {
    return cognitoRequest(
      {
        ...params,
        ClientId: this.userPoolClientId
      },
      ServiceTarget.RespondToAuthChallenge,
      this.cognitoEndpoint
    );
  }

  /**
   * Lists the devices associated with the user.
   * @param request Request to list devices.
   * @param request.AccessToken Access token of the current user.
   * @param request.Limit Maximum number of devices to return.
   * @param request.PaginationToken Pagination token to continue listing devices.
   * @returns
   */
  async listDevices(request: ListDevicesRequest): Promise<ListDevicesResponse> {
    return cognitoRequest(request, ServiceTarget.ListDevices, this.cognitoEndpoint);
  }

  /**
   * 
   * @param request Request to set user MFA preferences.
   * @param request.AccessToken Access token of the current user.
   * @param request.EmailMfaSettings Optional settings for email MFA.
   * @param request.SMSMfaSettings Optional settings for SMS MFA.
   * @param request.SoftwareTokenMfaSettings Optional settings for software token MFA.
   
   * @returns 
   */
  async setUserMFAPreference(request: SetUserMFAPreferenceRequest): Promise<void> {
    return cognitoRequest(request, ServiceTarget.SetUserMFAPreference, this.cognitoEndpoint);
  }

  /**
   * Updates the user attributes.
   *
   * @param userAttributes List of user attributes to update.
   * @param accessToken Access token of the current user.
   *
   * @throws {UpdateUserAttributesError}
   */
  async updateUserAttributes(userAttributes: UserAttribute[], accessToken: string) {
    const updateUserAttributesPayload = {
      UserAttributes: userAttributes,
      AccessToken: accessToken
    };

    await cognitoRequest(updateUserAttributesPayload, ServiceTarget.UpdateUserAttributes, this.cognitoEndpoint);
  }

  /**
   * Verifies a given user attribute
   *
   * @param attributeName Name of the attribute to verify
   * @param code  Verification code
   * @param accessToken Access token of the current user.
   *
   * @throws {VerifyUserAttributeError}
   */
  async verifyUserAttribute(attributeName: string, code: string, accessToken: string) {
    const verifyUserAttributePayload = {
      AttributeName: attributeName,
      Code: code,
      AccessToken: accessToken
    };

    await cognitoRequest(verifyUserAttributePayload, ServiceTarget.VerifyUserAttribute, this.cognitoEndpoint);
  }

  /**
   * Revokes all of the access tokens generated by, and at the same time as, the specified refresh token. After a token is revoked, you can't use the revoked token to access Amazon Cognito user APIs, or to authorize access to your resource server.
   *
   * @param refreshToken Refresh token from a previous session.
   * @param username Username is required when using a client secret and needs to be the cognito user id.
   * @throws {RevokeTokenError}
   */
  async revokeToken(refreshToken: string) {
    const revokeTokenPayload = {
      Token: refreshToken,
      ClientId: this.userPoolClientId,
      ClientSecret: this.clientSecret
    };

    await cognitoRequest(revokeTokenPayload, ServiceTarget.RevokeToken, this.cognitoEndpoint);
  }

  /**
   * Request forgot password.
   * @param username Username
   *
   * @throws {ForgotPasswordError}
   */
  async forgotPassword(username: string) {
    const forgotPasswordRequest: ForgotPasswordRequest = {
      ClientId: this.userPoolClientId,
      Username: username,
      SecretHash: this.clientSecret && (await calculateSecretHash(this.clientSecret, this.userPoolClientId, username))
    };

    await cognitoRequest(forgotPasswordRequest, ServiceTarget.ForgotPassword, this.cognitoEndpoint);
  }

  /**
   * Confirms the new password via the given code send via cognito triggered by @see forgotPassword .
   *
   * @param username Username
   * @param newPassword New password
   * @param confirmationCode Confirmation code which the user got through E-mail
   *
   * @throws {ConfirmForgotPasswordError}
   */
  async confirmForgotPassword(username: string, newPassword: string, confirmationCode: string) {
    const confirmForgotPasswordRequest: ConfirmForgotPasswordRequest = {
      ClientId: this.userPoolClientId,
      Username: username,
      ConfirmationCode: confirmationCode,
      Password: newPassword,
      SecretHash: this.clientSecret && (await calculateSecretHash(this.clientSecret, this.userPoolClientId, username))
    };

    await cognitoRequest(confirmForgotPasswordRequest, ServiceTarget.ConfirmForgotPassword, this.cognitoEndpoint);
  }

  /**
   * Triggers cognito to resend the confirmation code
   * @param username Username
   *
   * @throws {ResendConfirmationCodeError}
   */
  async resendConfirmationCode(username: string) {
    const resendConfirmationCodeRequest: ResendConfirmationCodeRequest = {
      ClientId: this.userPoolClientId,
      Username: username,
      SecretHash: this.clientSecret && (await calculateSecretHash(this.clientSecret, this.userPoolClientId, username))
    };

    await cognitoRequest(resendConfirmationCodeRequest, ServiceTarget.ResendConfirmationCode, this.cognitoEndpoint);
  }

  async startWebAuthnRegistration(
    request: StartWebAuthnRegistrationRequest
  ): Promise<StartWebAuthnRegistrationResponse> {
    const response = await cognitoRequest(request, ServiceTarget.StartWebAuthnRegistration, this.cognitoEndpoint);

    response.CredentialCreationOptions.challenge = base64UrlToUint8Array(
      response.CredentialCreationOptions.challenge as any
    );

    response.CredentialCreationOptions.user.id = base64UrlToUint8Array(
      response.CredentialCreationOptions.user.id as any
    );

    response.CredentialCreationOptions.excludeCredentials = (
      response.CredentialCreationOptions.excludeCredentials || []
    ).map((excludeCred: any) => ({
      ...excludeCred,
      id: base64UrlToUint8Array(excludeCred.id)
    }));

    return response;
  }

  /**
   * Completes registration of a passkey authenticator for the currently signed-in user.
   * @param request Request to complete WebAuthn registration.
   * @param request.AccessToken Access token of the current user.
   * @param request.Credential The credential object returned by the WebAuthn API.
   */
  async completeWebAuthnRegistration(request: CompleteWebAuthnRegistrationRequest): Promise<void> {
    await cognitoRequest(
      {
        AccessToken: request.AccessToken,
        Credential: publicKeyCredentialToJSON(request.Credential)
      },
      ServiceTarget.CompleteWebAuthnRegistration,
      this.cognitoEndpoint
    );
  }

  /**
   * Deletes a registered passkey, or WebAuthn, authenticator for the currently signed-in user.
   *
   * @param request Request to delete a WebAuthn credential.
   * @param request.AccessToken Access token of the current user.
   * @param request.CredentialId The ID of the credential to delete.
   */
  async deleteWebAuthnCredential(request: DeleteWebAuthnCredentialRequest): Promise<void> {
    await cognitoRequest(request, ServiceTarget.DeleteWebAuthnCredential, this.cognitoEndpoint);
  }

  /**
   * Lists all registered WebAuthn credentials for the currently signed-in user.
   *
   * @param request Request to list WebAuthn credentials.
   * @param request.AccessToken Access token of the current user.
   * @param request.MaxResults Maximum number of credentials to return.
   * @param request.NextToken Pagination token to continue listing credentials.
   * @returns
   */
  async listWebAuthnCredentials(request: ListWebAuthnCredentialsRequest): Promise<ListWebAuthnCredentialsResponse> {
    const response = await cognitoRequest(request, ServiceTarget.ListWebAuthnCredentials, this.cognitoEndpoint);

    return response;
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
  async generateOAuthSignInUrl(identityProvider?: IdentityProvider) {
    if (this.oAuth === undefined) {
      throw Error('You have to define oAuth options to use generateFederatedSignUrl');
    }

    const state = (await randomBytes(32)).toString('hex');
    const pkce = (await randomBytes(128)).toString('hex');

    const code_challenge = uint8ArrayToBase64String(await digest('SHA-256', uint8ArrayFromString(pkce)))
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

    return {
      url: `${this.oAuth.cognitoDomain}/oauth2/authorize?${queryParams.toString()}`,
      state,
      pkce
    };
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
  async handleCodeFlow(returnUrl: string, pkce: string, state: string): Promise<AuthenticationResult> {
    if (this.oAuth === undefined) {
      throw Error('You have to define oAuth options to use handleCodeFlow');
    }

    const url = new URL(returnUrl);
    const code = url.searchParams.get('code');

    if (code === null) {
      throw Error('code parameter is missing from return url.');
    }

    if (url.searchParams.get('state') !== state) {
      throw Error('State parameter does not match.');
    }

    const urlParams = new URLSearchParams();

    urlParams.append('grant_type', 'authorization_code');
    urlParams.append('code', code);
    urlParams.append('client_id', this.userPoolClientId);
    urlParams.append('redirect_uri', this.oAuth.redirectUrl);
    urlParams.append('code_verifier', pkce);

    const tokenEndpoint = `${this.oAuth.cognitoDomain}/oauth2/token`;

    const response = await fetch(tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: urlParams.toString()
    });

    const { access_token, refresh_token, id_token, expires_in, error } = await response.json();

    if (error) {
      throw new Error(error);
    }

    return adaptExpiresIn({
      AccessToken: access_token,
      RefreshToken: refresh_token,
      IdToken: id_token,
      ExpiresIn: expires_in
    });
  }

  /**
   * Invalidates the identity, access, and refresh tokens that Amazon Cognito issued to a user. Call this operation when your user signs out of your app. This results in the following behavior.
   * @param accessToken Access token of the current user.
   */
  async globalSignOut(accessToken: string) {
    const globalSignOutPayload = {
      AccessToken: accessToken
    };

    await cognitoRequest(globalSignOutPayload, ServiceTarget.GlobalSignOut, this.cognitoEndpoint);
  }
}
