import { CognitoClient } from '../cognito-client.js';
import {
  AdminDeleteUserCommand,
  CognitoIdentityProviderClient,
  ListUsersCommand,
  AdminUpdateUserAttributesCommand,
  AdminConfirmSignUpCommand
} from '@aws-sdk/client-cognito-identity-provider';
import { beforeEach, describe, expect, test } from 'vitest';

const email = process.env.EMAIL!;
const password = process.env.PASSWORD!;
const newPassword = process.env.NEW_PASSWORD!;
const UserPoolId = process.env.COGNITO_USER_POOL_ID!;
const givenName = process.env.GIVEN_NAME!;
const familyName = process.env.FAMILY_NAME!;
const region = process.env.REGION!;

const cognitoIdentityProviderClient = new CognitoIdentityProviderClient({
  region,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID!,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY!,
    sessionToken: process.env.AWS_SESSION_TOKEN!
  }
});

beforeEach(async () => {
  const { Users } = await cognitoIdentityProviderClient.send(
    new ListUsersCommand({
      UserPoolId
    })
  );

  if (Users) {
    for (const user of Users) {
      await cognitoIdentityProviderClient.send(
        new AdminDeleteUserCommand({
          UserPoolId,
          Username: user.Username
        })
      );
    }
  }
});

async function confirmUser(userName: string) {
  await cognitoIdentityProviderClient.send(
    new AdminUpdateUserAttributesCommand({
      UserPoolId,
      Username: userName,
      UserAttributes: [
        {
          Name: 'email_verified',
          Value: 'true'
        }
      ]
    })
  );
  await cognitoIdentityProviderClient.send(
    new AdminConfirmSignUpCommand({
      UserPoolId,
      Username: userName
    })
  );
}

async function cognitoClientTestWorkflow(client: CognitoClient) {
  const user = await client.signUp(email, password, [
    {
      Name: 'given_name',
      Value: givenName
    },
    {
      Name: 'family_name',
      Value: familyName
    },
    {
      Name: 'email',
      Value: email
    }
  ]);

  // await client.resendConfirmationCode(email);

  expect(user.confirmed).toBe(false);
  expect(user.id).toBeDefined();

  await confirmUser(email);

  let session = await client.authenticateUser(email, password);

  expect(session.accessToken).toBeDefined();
  expect(session.idToken).toBeDefined();
  expect(session.refreshToken).toBeDefined();
  expect(session.expiresIn).toBeDefined();

  session = await client.authenticateUserSrp(email, password);

  expect(session.accessToken).toBeDefined();
  expect(session.idToken).toBeDefined();
  expect(session.refreshToken).toBeDefined();
  expect(session.expiresIn).toBeDefined();

  session = await client.refreshSession(session.refreshToken, user.id);

  expect(session.accessToken).toBeDefined();
  expect(session.idToken).toBeDefined();
  expect(session.refreshToken).toBeDefined();
  expect(session.expiresIn).toBeDefined();

  await client.updateUserAttributes(
    [
      {
        Name: 'given_name',
        Value: 'new name'
      }
    ],
    session.accessToken
  );

  await client.changePassword(password, newPassword, session.accessToken);
  session = await client.authenticateUserSrp(email, newPassword);

  await client.revokeToken(session.refreshToken);
  await client.forgotPassword(email);

  session = await client.authenticateUserSrp(email, newPassword);
  await client.globalSignOut(session.accessToken);
}

describe('cognito client integration test', () => {
  test('cognito client with client secret', async () => {
    await cognitoClientTestWorkflow(
      new CognitoClient({
        userPoolId: process.env.COGNITO_USER_POOL_ID!,
        userPoolClientId: process.env.COGNITO_USER_POOL_WITH_SECRET_CLIENT_ID!,
        clientSecret: process.env.COGNITO_USER_POOL_CLIENT_SECRET!
      })
    );
  });
  test('cognito client without client secret', async () => {
    await cognitoClientTestWorkflow(
      new CognitoClient({
        userPoolId: process.env.COGNITO_USER_POOL_ID!,
        userPoolClientId: process.env.COGNITO_USER_POOL_WITHOUT_SECRET_CLIENT_ID!
      })
    );
  });
});
