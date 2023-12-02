#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { CognitoStack } from '../lib/cognito-stack';

const env = {
  account: process.env.CDK_DEPLOY_ACCOUNT || process.env.CDK_DEFAULT_ACCOUNT,
  region: process.env.CDK_DEPLOY_REGION || process.env.CDK_DEFAULT_REGION
};

console.log(`Deploying to ${env.account}/${env.region}`);

const app = new cdk.App();
new CognitoStack(app, 'CognitoStack', {
  env
});
