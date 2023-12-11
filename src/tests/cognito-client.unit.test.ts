import 'isomorphic-fetch';
import { GenericContainer, StartedTestContainer } from 'testcontainers';
import {
  AuthenticationResult,
  CognitoClient,
  CognitoIdentityProvider,
  CognitoServiceTarget,
  OAuth2Props,
  authResultToSession,
  cognitoRequest
} from '../cognito-client.js';
import { newUser, setupCognito, user } from './test-utils.js';
import { expect, test, describe, beforeAll, afterAll } from 'vitest';
import { vi } from 'vitest';
import createFetchMock from 'vitest-fetch-mock';
import { beforeEach } from 'vitest';

import { UserPoolClientType, UserPoolType } from '@aws-sdk/client-cognito-identity-provider';
import {
  ChangePasswordException,
  CognitoChangePasswordError,
  CognitoConfirmForgotPasswordError,
  CognitoConfirmSignUpError,
  CognitoForgotPasswordError,
  CognitoGlobalSignOutError,
  CognitoInitAuthError,
  CognitoResendConfirmationCodeError,
  CognitoRespondToAuthChallengeError,
  CognitoRevokeTokenError,
  CognitoSignUpError,
  CognitoUpdateUserAttributesError,
  CognitoVerifyUserAttributeError,
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
  VerifyUserAttributeException
} from '../error.js';

const fetchMocker = createFetchMock(vi);

describe('Cognito Client', () => {
  let cognitoClient: CognitoClient;
  let container: StartedTestContainer;

  const oAuth2: OAuth2Props = {
    cognitoDomain: 'http://localhost',
    redirectUrl: 'http://localhost',
    responseType: 'code',
    scopes: ['email openid']
  };

  let userPoolClient: UserPoolClientType;
  let userPool: UserPoolType;

  beforeAll(async () => {
    const cognitoPort = 9229;
    container = await new GenericContainer('jagregory/cognito-local').withExposedPorts(cognitoPort).start();
    const cognitoEndpoint = `http://localhost:${container.getMappedPort(cognitoPort)}`;

    const cognitoResult = await setupCognito(cognitoEndpoint);

    userPoolClient = cognitoResult.userPoolClient;
    userPool = cognitoResult.userPool;

    cognitoClient = new CognitoClient({
      userPoolId: userPool.Id!,
      userPoolClientId: userPoolClient.ClientId!,
      clientSecret: userPoolClient.ClientSecret!,
      endpoint: cognitoEndpoint,
      oAuth2: oAuth2
    });

    await cognitoClient.authenticateUser(user.email, user.password);
  });

  afterAll(async () => {
    await container.stop();
  });

  beforeEach(() => {
    fetchMocker.mockReset();
  });

  test('authenticateUserSrp: TODO', async () => {
    // TODO: Currently SRP auth is not supported through cognito-local
    // const session = await cognitoClient.authenticateUserSrp(user.name, user.password);
    // expect(session).toEqual(await cognitoClient.getSession());
    expect(true).toBe(true);
  });

  test('signUp', async () => {
    const { id, confirmed } = await cognitoClient.signUp(newUser.email, newUser.password, [
      { Name: 'givenName', Value: newUser.givenName },
      { Name: 'familyName', Value: newUser.familyName }
    ]);
    expect(id).toBeDefined();
    expect(confirmed).toBe(false);
  });

  test('changePassword', async () => {
    const newPassword = 'newPassword';
    expect(cognitoClient.authenticateUser(user.email, newPassword)).rejects.toThrow();

    const session = await cognitoClient.authenticateUser(user.email, user.password);
    await cognitoClient.changePassword(user.password, newPassword, session.accessToken);
    await cognitoClient.revokeToken(session.refreshToken);
    expect(cognitoClient.authenticateUser(user.email, user.password)).rejects.toThrow();
    await cognitoClient.authenticateUser(user.email, newPassword);
  });
  test('generateOAuthSignInUrl', async () => {
    const _test = async (cb: (searchParams: URLSearchParams) => void, identityProvider?: CognitoIdentityProvider) => {
      const { url, state } = await cognitoClient.generateOAuthSignInUrl(identityProvider);
      const { searchParams } = new URL(url);

      expect(searchParams.get('redirect_uri')).toBe(oAuth2.redirectUrl);
      expect(searchParams.get('response_type')).toBe(oAuth2.responseType);
      expect(searchParams.get('client_id')).toBe(userPoolClient.ClientId!);
      expect(searchParams.get('scope')).toBe(oAuth2.scopes.join(' '));
      expect(searchParams.get('state')).toBe(state);
      expect(searchParams.get('code_challenge')).toBeDefined();
      expect(searchParams.get('code_challenge_method')).toBe('S256');

      cb(searchParams);
    };

    await _test((searchParams: URLSearchParams) => {
      expect(searchParams.get('identity_provider')).toBeNull();
    });

    await _test((searchParams: URLSearchParams) => {
      expect(searchParams.get('identity_provider')).toBe(CognitoIdentityProvider.Apple);
    }, CognitoIdentityProvider.Apple);
  });

  test('authResultToSession', () => {
    const now = new Date();
    const authResult: AuthenticationResult = {
      AccessToken: 'aaaa',
      ExpiresIn: 60,
      IdToken: 'bbbb',
      RefreshToken: 'cccc'
    };
    const session = authResultToSession(authResult);
    expect(session.accessToken).toBe(authResult.AccessToken);
    expect(session.idToken).toBe(authResult.IdToken);
    expect(session.refreshToken).toBe(authResult.RefreshToken);
    expect(session.expiresIn).toBe(authResult.ExpiresIn * 1000 + now.getTime());
  });

  test('cognitoRequest', async () => {
    fetchMocker.enableMocks();

    fetchMocker.mockResponses(
      [
        JSON.stringify({
          message: 'test',
          code: 'code'
        }),
        {
          status: 400,
          headers: {
            'X-Amzn-ErrorMessage': 'test',
            'X-Amzn-ErrorType': 'code'
          }
        }
      ],
      [
        JSON.stringify({
          message: 'test',
          code: 'code'
        }),
        {
          status: 400
        }
      ],
      [
        JSON.stringify({
          Message: 'test',
          code: 'code'
        }),
        {
          status: 400
        }
      ],
      [
        JSON.stringify({}),
        {
          status: 400,
          headers: {
            'X-Amzn-ErrorMessage': 'test',
            'X-Amzn-ErrorType': 'code'
          }
        }
      ],
      [
        JSON.stringify({}),
        {
          status: 400,
          headers: {
            'X-Amzn-ErrorMessage': 'test',
            'X-Amzn-ErrorType': 'code:'
          }
        }
      ],
      [
        JSON.stringify({}),
        {
          status: 400,
          headers: {
            'X-Amzn-ErrorMessage': 'test',
            'X-Amzn-ErrorType': 'code,'
          }
        }
      ]
    );

    expect(cognitoRequest({}, CognitoServiceTarget.InitiateAuth, 'http://localhost')).rejects.toThrowError(
      new CognitoInitAuthError('test', 'code' as InitiateAuthException)
    );

    expect(cognitoRequest({}, CognitoServiceTarget.InitiateAuth, 'http://localhost')).rejects.toThrowError(
      new CognitoInitAuthError('test', 'code' as InitiateAuthException)
    );

    expect(cognitoRequest({}, CognitoServiceTarget.InitiateAuth, 'http://localhost')).rejects.toThrowError(
      new CognitoInitAuthError('test', 'code' as InitiateAuthException)
    );

    expect(cognitoRequest({}, CognitoServiceTarget.InitiateAuth, 'http://localhost')).rejects.toThrowError(
      new CognitoInitAuthError('test', 'code' as InitiateAuthException)
    );

    expect(cognitoRequest({}, CognitoServiceTarget.InitiateAuth, 'http://localhost')).rejects.toThrowError(
      new CognitoInitAuthError('test', 'code' as InitiateAuthException)
    );

    expect(cognitoRequest({}, CognitoServiceTarget.InitiateAuth, 'http://localhost')).rejects.toThrowError(
      new CognitoInitAuthError('test', 'code' as InitiateAuthException)
    );

    fetchMocker.mockResponse(
      JSON.stringify({
        message: 'test',
        code: 'code'
      }),
      {
        status: 400,
        headers: {
          'X-Amzn-ErrorMessage': 'test',
          'X-Amzn-ErrorType': 'code'
        }
      }
    );

    expect(cognitoRequest({}, CognitoServiceTarget.RespondToAuthChallenge, 'http://localhost')).rejects.toThrowError(
      new CognitoRespondToAuthChallengeError('test', 'code' as RespondToAuthChallengeException)
    );

    expect(cognitoRequest({}, CognitoServiceTarget.SignUp, 'http://localhost')).rejects.toThrowError(
      new CognitoSignUpError('test', 'code' as SignUpException)
    );

    expect(cognitoRequest({}, CognitoServiceTarget.ConfirmSignUp, 'http://localhost')).rejects.toThrowError(
      new CognitoConfirmSignUpError('test', 'code' as ConfirmSignUpException)
    );

    expect(cognitoRequest({}, CognitoServiceTarget.ChangePassword, 'http://localhost')).rejects.toThrowError(
      new CognitoChangePasswordError('test', 'code' as ChangePasswordException)
    );

    expect(cognitoRequest({}, CognitoServiceTarget.RevokeToken, 'http://localhost')).rejects.toThrowError(
      new CognitoRevokeTokenError('test', 'code' as RevokeTokenException)
    );

    expect(cognitoRequest({}, CognitoServiceTarget.ForgotPassword, 'http://localhost')).rejects.toThrowError(
      new CognitoForgotPasswordError('test', 'code' as ForgotPasswordException)
    );

    expect(cognitoRequest({}, CognitoServiceTarget.ConfirmForgotPassword, 'http://localhost')).rejects.toThrowError(
      new CognitoConfirmForgotPasswordError('test', 'code' as ConfirmForgotPasswordException)
    );

    expect(cognitoRequest({}, CognitoServiceTarget.ResendConfirmationCode, 'http://localhost')).rejects.toThrowError(
      new CognitoResendConfirmationCodeError('test', 'code' as ResendConfirmationException)
    );

    expect(cognitoRequest({}, CognitoServiceTarget.UpdateUserAttributes, 'http://localhost')).rejects.toThrowError(
      new CognitoUpdateUserAttributesError('test', 'code' as UpdateUserAttributesException)
    );

    expect(cognitoRequest({}, CognitoServiceTarget.VerifyUserAttribute, 'http://localhost')).rejects.toThrowError(
      new CognitoVerifyUserAttributeError('test', 'code' as VerifyUserAttributeException)
    );

    expect(cognitoRequest({}, CognitoServiceTarget.GlobalSignOut, 'http://localhost')).rejects.toThrowError(
      new CognitoGlobalSignOutError('test', 'code' as GlobalSignOutException)
    );
  });
});
