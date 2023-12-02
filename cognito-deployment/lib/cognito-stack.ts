import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as iam from 'aws-cdk-lib/aws-iam';

export class CognitoStack extends cdk.Stack {
  createGitHubOpenIdConnectProvider(repoName: string, branches: string[], userPool: cognito.UserPool) {
    const githubOpenIdConnect = new iam.OpenIdConnectProvider(this, 'GitHubOpenIdConnectProvider', {
      url: 'https://token.actions.githubusercontent.com',
      clientIds: ['sts.amazonaws.com'],
      thumbprints: ['ffffffffffffffffffffffffffffffffffffffff']
    });

    new iam.Role(this, 'github-workflow-role', {
      roleName: 'github-workflow-role',
      assumedBy: new iam.OpenIdConnectPrincipal(githubOpenIdConnect, {
        StringEquals: {
          'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com',
          'token.actions.githubusercontent.com:sub': branches.map(branch => `repo:${repoName}:ref:refs/heads/${branch}`)
        }
      }),
      inlinePolicies: {
        GitHubWorkflowPolicy: new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({
              actions: [
                'cognito-idp:AdminDeleteUser',
                'cognito-idp:ListUsers',
                'cognito-idp:AdminUpdateUserAttributes',
                'cognito-idp:AdminConfirmSignUp'
              ],
              resources: [`arn:aws:cognito-idp:${this.region}:${this.account}:userpool/${userPool.userPoolId}`]
            })
          ]
        })
      }
    });
  }

  createCognitoUserPool() {
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

    const userPoolClientWithSecret = new cognito.UserPoolClient(this, 'CognitoUserPoolClientWithSecret', {
      generateSecret: true,
      userPool,
      authFlows: {
        userPassword: true,
        userSrp: true
      }
    });

    const userPoolClientWithoutSecret = new cognito.UserPoolClient(this, 'CognitoUserPoolClientWithoutSecret', {
      generateSecret: false,
      userPool,
      authFlows: {
        userPassword: true,
        userSrp: true
      }
    });

    return {
      userPool,
      userPoolClientWithSecret,
      userPoolClientWithoutSecret
    };
  }

  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const { userPool } = this.createCognitoUserPool();
    this.createGitHubOpenIdConnectProvider('vardario/cognito-client', ['release'], userPool);
  }
}
