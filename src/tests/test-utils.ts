import {
  AdminCreateUserCommand,
  AdminSetUserPasswordCommand,
  CognitoIdentityProviderClient,
  CreateUserPoolClientCommand,
  CreateUserPoolCommand
} from '@aws-sdk/client-cognito-identity-provider';

import { AttributeDataType } from '@aws-sdk/client-cognito-identity-provider';
import { JSDOM } from 'jsdom';

export const user = {
  email: 'sahin@test.com',
  password: 'password',
  givenName: 'Sahin',
  familyName: 'Sahin'
};

export const newUser = {
  email: 'john@test.com',
  password: 'password',
  givenName: 'John',
  familyName: 'John'
};

export async function setupCognito(endpoint: string) {
  const awsCognitoClient = new CognitoIdentityProviderClient({
    endpoint: endpoint,
    credentials: {
      accessKeyId: 'test',
      secretAccessKey: 'test'
    },
    region: 'eu-central-1'
  });

  const createPoolResult = await awsCognitoClient.send(
    new CreateUserPoolCommand({
      PoolName: 'TestPool',
      Schema: [
        {
          Name: 'email',
          AttributeDataType: AttributeDataType.STRING,
          Required: true
        },
        {
          Name: 'givenName',
          AttributeDataType: AttributeDataType.STRING,
          Required: true
        },
        {
          Name: 'familyName',
          AttributeDataType: AttributeDataType.STRING,
          Required: true
        }
      ]
    })
  );

  const createUserPoolClientResult = await awsCognitoClient.send(
    new CreateUserPoolClientCommand({
      ClientName: 'TestClient',
      UserPoolId: createPoolResult.UserPool?.Id,
      GenerateSecret: true
    })
  );

  await awsCognitoClient.send(
    new AdminCreateUserCommand({
      UserPoolId: createPoolResult.UserPool?.Id,
      Username: user.email,
      MessageAction: 'SUPPRESS',
      UserAttributes: [
        {
          Name: 'givenName',
          Value: user.givenName
        },
        {
          Name: 'familyName',
          Value: user.familyName
        }
      ]
    })
  );

  await awsCognitoClient.send(
    new AdminSetUserPasswordCommand({
      UserPoolId: createPoolResult.UserPool?.Id,
      Username: user.email,
      Password: user.password,
      Permanent: true
    })
  );

  return {
    userPool: createPoolResult.UserPool!,
    userPoolClient: createUserPoolClientResult.UserPoolClient!
  };
}

export function setupJsDom() {
  const dom = new JSDOM('', {
    url: 'http://localhost'
  });
  global.document = dom.window.document;
  global.window = dom.window as any;
}
