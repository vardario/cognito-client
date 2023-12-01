import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as cognito from 'aws-cdk-lib/aws-cognito';

export class CognitoStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const userPool = new cognito.UserPool(this, 'CognitoUserPool', {
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      selfSignUpEnabled: true,
      signInAliases: { email: true },
      keepOriginal: { email: true },
      customAttributes: {},
      standardAttributes: {
        email: {
          required: true
        },
        givenName: {
          required: true
        },
        familyName: {
          required: true
        }
      }
    });

    new cognito.UserPoolClient(this, 'CognitoUserPoolClientWithSecret', {
      generateSecret: true,
      userPool,
      authFlows: {
        userPassword: true,
        userSrp: true
      }
    });

    new cognito.UserPoolClient(this, 'CognitoUserPoolClientWithoutSecret', {
      generateSecret: false,
      userPool,
      authFlows: {
        userPassword: true,
        userSrp: true
      }
    });
  }
}
