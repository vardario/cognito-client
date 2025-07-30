# Cognito Client Library for User Authentication and Management

This project provides a comprehensive Cognito client library for user authentication and management in web applications. It offers a robust set of functionalities to interact with AWS Cognito services, including user sign-up, authentication, password management, and OAuth2 integration.

The library is designed to simplify the process of integrating Cognito-based authentication into your applications, providing a clean and easy-to-use interface for developers. It handles complex operations such as Secure Remote Password (SRP) authentication, token management, and error handling, allowing developers to focus on building their application logic.

## Repository Structure

```
.
├── cognito-deployment/
│   ├── bin/
│   │   └── cognito-deployment.ts
│   ├── lib/
│   │   └── cognito-stack.ts
│   ├── cdk.json
│   ├── package.json
│   └── tsconfig.json
├── src/
│   ├── tests/
│   │   ├── cognito-client.unit.test.ts
│   │   ├── integration.test.ts
│   │   ├── test-utils.ts
│   │   └── utils.unit.test.ts
│   ├── bigint-math.ts
│   ├── cognito-client.ts
│   ├── error.ts
│   ├── index.ts
│   └── utils.ts
├── package.json
├── pnpm-lock.yaml
├── tsconfig.json
└── vite.config.ts
```

### Key Files:

- `src/cognito-client.ts`: Main Cognito client implementation
- `src/utils.ts`: Utility functions for cryptographic operations
- `src/error.ts`: Custom error types for Cognito operations
- `cognito-deployment/lib/cognito-stack.ts`: CDK stack for Cognito infrastructure

### Important Integration Points:

- `src/index.ts`: Entry point for the library
- `cognito-deployment/bin/cognito-deployment.ts`: CDK app entry point for Cognito deployment

## Usage Instructions

### Installation

Prerequisites:

- Node.js (v14 or later)
- pnpm (v6 or later)

To install the library, run:

```bash
pnpm install @vardario/cognito-client
```

### Getting Started

1. Import the CognitoClient:

```typescript
import { CognitoClient } from '@vardario/cognito-client';
```

2. Initialize the client:

```typescript
const cognitoClient = new CognitoClient({
  userPoolId: 'your-user-pool-id',
  userPoolClientId: 'your-user-pool-client-id',
  clientSecret: 'your-client-secret', // Optional
  endpoint: 'your-cognito-endpoint', // Optional
  oAuth2: {
    cognitoDomain: 'your-cognito-domain',
    redirectUrl: 'your-redirect-url',
    responseType: 'code',
    scopes: ['email', 'openid']
  }
});
```

3. Use the client to perform Cognito operations:

```typescript
// Sign up a new user
const { id, confirmed } = await cognitoClient.signUp('user@example.com', 'password', [
  { Name: 'givenName', Value: 'John' },
  { Name: 'familyName', Value: 'Doe' }
]);

// Authenticate a user
const session = await cognitoClient.authenticateUser('user@example.com', 'password');

// Change password
await cognitoClient.changePassword('oldPassword', 'newPassword', session.accessToken);

// Generate OAuth2 sign-in URL
const { url, state } = await cognitoClient.generateOAuthSignInUrl();
```

### Configuration Options

The `CognitoClient` constructor accepts the following options:

- `userPoolId`: Cognito User Pool ID
- `userPoolClientId`: Cognito User Pool Client ID
- `clientSecret`: (Optional) Cognito User Pool Client Secret
- `endpoint`: (Optional) Custom Cognito endpoint for testing
- `oAuth2`: (Optional) OAuth2 configuration object

### Common Use Cases

1. User Registration and Confirmation:

```typescript
const { id, confirmed } = await cognitoClient.signUp('user@example.com', 'password', [
  { Name: 'givenName', Value: 'John' },
  { Name: 'familyName', Value: 'Doe' }
]);

if (!confirmed) {
  await cognitoClient.confirmSignUp('user@example.com', 'confirmationCode');
}
```

2. User Authentication:

```typescript
const session = await cognitoClient.authenticateUser('user@example.com', 'password');
console.log('Access Token:', session.accessToken);
console.log('ID Token:', session.idToken);
console.log('Refresh Token:', session.refreshToken);
```

3. Password Reset:

```typescript
await cognitoClient.forgotPassword('user@example.com');
await cognitoClient.confirmForgotPassword('user@example.com', 'newPassword', 'confirmationCode');
```

4. OAuth2 Authentication:

```typescript
const { url, state } = await cognitoClient.generateOAuthSignInUrl();
// Redirect the user to the generated URL
```

### Testing & Quality

To run the test suite:

```bash
pnpm test
```

For integration tests:

```bash
pnpm integration-test
```

### Troubleshooting

1. Authentication Failures:

   - Problem: User unable to authenticate
   - Error message: "NotAuthorizedException: Incorrect username or password."
   - Diagnostic steps:
     1. Verify the user's email and password
     2. Check if the user's account is confirmed
     3. Ensure the Cognito User Pool and Client IDs are correct
   - Solution: If the user's account is not confirmed, use the `confirmSignUp` method to confirm it.

2. Token Expiration:

   - Problem: Session tokens become invalid
   - Error message: "NotAuthorizedException: Access Token has expired"
   - Diagnostic steps:
     1. Check the `expiresIn` property of the session object
     2. Verify the system clock is synchronized
   - Solution: Implement token refresh logic using the `refreshSession` method before the token expires.

3. OAuth2 Redirect Issues:
   - Problem: OAuth2 redirect fails
   - Error message: "OAuth2 state mismatch"
   - Diagnostic steps:
     1. Verify the `redirectUrl` in the OAuth2 configuration matches the one set in the Cognito User Pool client
     2. Ensure the state parameter is properly handled in the redirect flow
   - Solution: Store and verify the state parameter on the client-side to prevent CSRF attacks.

### Debugging

To enable debug mode:

```typescript
import { CognitoClient } from '@vardario/cognito-client';

const cognitoClient = new CognitoClient({
  // ... other options
  debug: true
});
```

Debug logs will be output to the console. For Node.js environments, logs are written to `~/.cognito-client/debug.log`.

## Data Flow

The Cognito Client Library facilitates the authentication and user management flow between your application and AWS Cognito. Here's a high-level overview of the data flow:

1. User Registration:
   Application -> Cognito Client -> AWS Cognito
   (User data) -> (SignUp request) -> (Create user)

2. User Authentication:
   Application -> Cognito Client -> AWS Cognito
   (Credentials) -> (InitiateAuth) -> (AuthenticationResult)
3. Token Refresh:
   Application -> Cognito Client -> AWS Cognito
   (RefreshToken) -> (InitiateAuth) -> (New AccessToken)

4. User Attribute Management:
   Application -> Cognito Client -> AWS Cognito
   (AttributeUpdates) -> (UpdateUserAttributes) -> (Confirmation)

```
+-------------+     +-----------------+     +-------------+
| Application |<--->| Cognito Client |<--->| AWS Cognito |
+-------------+     +-----------------+     +-------------+
       ^                    ^                     ^
       |                    |                     |
       v                    v                     v
  User Interface       Token Management    User Data Storage
```

Note: The Cognito Client handles the complexities of SRP authentication, HMAC signing, and token management internally, simplifying the integration for developers.

## Infrastructure

The project includes a CDK stack for deploying the necessary Cognito infrastructure. Key resources defined in the `CognitoStack` include:

- UserPool: Cognito User Pool for user management

  - Type: `cognito.UserPool`
  - Purpose: Stores user accounts and handles authentication

- UserPoolClientWithSecret: XXXXXXX User Pool Client with a generated secret

  - Type: `cognito.UserPoolClient`
  - Purpose: Allows server-side applications to interact with the User Pool

- UserPoolClientWithoutSecret: XXXXXXX User Pool Client without a secret

  - Type: `cognito.UserPoolClient`
  - Purpose: Allows client-side applications to interact with the User Pool

- GitHubOpenIdConnectProvider: IAM OpenID Connect provider for GitHub Actions

  - Type: `iam.OpenIdConnectProvider`
  - Purpose: Enables GitHub Actions to assume IAM roles

- GitHubWorkflowRole: IAM role for GitHub Actions
  - Type: `iam.Role`
  - Purpose: Grants permissions to GitHub Actions for managing Cognito users

To deploy the infrastructure:

1. Configure your AWS credentials
2. Navigate to the `cognito-deployment` directory
3. Run `pnpm cdk deploy`

This will create the Cognito User Pool and associated resources in your AWS account.
