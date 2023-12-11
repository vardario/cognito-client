export enum AssociateSoftwareTokenException {
  ConcurrentModificationException = 'ConcurrentModificationException',
  ForbiddenException = 'ForbiddenException',
  InternalErrorException = 'InternalErrorException',
  InvalidParameterException = 'InvalidParameterException',
  NotAuthorizedException = 'NotAuthorizedException',
  ResourceNotFoundException = 'ResourceNotFoundException',
  SoftwareTokenMFANotFoundException = 'SoftwareTokenMFANotFoundException'
}

export enum ChangePasswordException {
  ForbiddenException = 'ForbiddenException',
  InternalErrorException = 'InternalErrorException',
  InvalidParameterException = 'InvalidParameterException',
  InvalidPasswordException = 'InvalidPasswordException',
  LimitExceededException = 'LimitExceededException',
  NotAuthorizedException = 'NotAuthorizedException',
  PasswordResetRequiredException = 'PasswordResetRequiredException',
  ResourceNotFoundException = 'ResourceNotFoundException',
  TooManyRequestsException = 'TooManyRequestsException',
  UserNotConfirmedException = 'UserNotConfirmedException',
  UserNotFoundException = 'UserNotFoundException'
}

export enum ConfirmDeviceException {
  ForbiddenException = 'ForbiddenException',
  InternalErrorException = 'InternalErrorException',
  InvalidLambdaResponseException = 'InvalidLambdaResponseException',
  InvalidParameterException = 'InvalidParameterException',
  InvalidPasswordException = 'InvalidPasswordException',
  InvalidUserPoolConfigurationException = 'InvalidUserPoolConfigurationException',
  NotAuthorizedException = 'NotAuthorizedException',
  PasswordResetRequiredException = 'PasswordResetRequiredException',
  ResourceNotFoundException = 'ResourceNotFoundException',
  TooManyRequestsException = 'TooManyRequestsException',
  UsernameExistsException = 'UsernameExistsException',
  UserNotConfirmedException = 'UserNotConfirmedException',
  UserNotFoundException = 'UserNotFoundException'
}

export enum ConfirmForgotPasswordException {
  CodeMismatchException = 'CodeMismatchException',
  ExpiredCodeException = 'ExpiredCodeException',
  ForbiddenException = 'ForbiddenException',
  InternalErrorException = 'InternalErrorException',
  InvalidLambdaResponseException = 'InvalidLambdaResponseException',
  InvalidParameterException = 'InvalidParameterException',
  InvalidPasswordException = 'InvalidPasswordException',
  LimitExceededException = 'LimitExceededException',
  NotAuthorizedException = 'NotAuthorizedException',
  ResourceNotFoundException = 'ResourceNotFoundException',
  TooManyFailedAttemptsException = 'TooManyFailedAttemptsException',
  TooManyRequestsException = 'TooManyRequestsException',
  UnexpectedLambdaException = 'UnexpectedLambdaException',
  UserLambdaValidationException = 'UserLambdaValidationException',
  UserNotConfirmedException = 'UserNotConfirmedException',
  UserNotFoundException = 'UserNotFoundException'
}

export enum ConfirmSignUpException {
  AliasExistsException = 'AliasExistsException',
  CodeMismatchException = 'CodeMismatchException',
  ExpiredCodeException = 'ExpiredCodeException',
  ForbiddenException = 'ForbiddenException',
  InternalErrorException = 'InternalErrorException',
  InvalidLambdaResponseException = 'InvalidLambdaResponseException',
  InvalidParameterException = 'InvalidParameterException',
  LimitExceededException = 'LimitExceededException',
  NotAuthorizedException = 'NotAuthorizedException',
  ResourceNotFoundException = 'ResourceNotFoundException',
  TooManyFailedAttemptsException = 'TooManyFailedAttemptsException',
  TooManyRequestsException = 'TooManyRequestsException',
  UnexpectedLambdaException = 'UnexpectedLambdaException',
  UserLambdaValidationException = 'UserLambdaValidationException',
  UserNotFoundException = 'UserNotFoundException'
}

export enum DeleteUserAttributesException {
  ForbiddenException = 'ForbiddenException',
  InternalErrorException = 'InternalErrorException',
  InvalidParameterException = 'InvalidParameterException',
  NotAuthorizedException = 'NotAuthorizedException',
  PasswordResetRequiredException = 'PasswordResetRequiredException',
  ResourceNotFoundException = 'ResourceNotFoundException',
  TooManyRequestsException = 'TooManyRequestsException',
  UserNotConfirmedException = 'UserNotConfirmedException',
  UserNotFoundException = 'UserNotFoundException'
}

export enum DeleteUserException {
  ForbiddenException = 'ForbiddenException',
  InternalErrorException = 'InternalErrorException',
  InvalidParameterException = 'InvalidParameterException',
  NotAuthorizedException = 'NotAuthorizedException',
  PasswordResetRequiredException = 'PasswordResetRequiredException',
  ResourceNotFoundException = 'ResourceNotFoundException',
  TooManyRequestsException = 'TooManyRequestsException',
  UserNotConfirmedException = 'UserNotConfirmedException',
  UserNotFoundException = 'UserNotFoundException'
}

export enum ForgetDeviceException {
  ForbiddenException = 'ForbiddenException',
  InternalErrorException = 'InternalErrorException',
  InvalidParameterException = 'InvalidParameterException',
  InvalidUserPoolConfigurationException = 'InvalidUserPoolConfigurationException',
  NotAuthorizedException = 'NotAuthorizedException',
  PasswordResetRequiredException = 'PasswordResetRequiredException',
  ResourceNotFoundException = 'ResourceNotFoundException',
  TooManyRequestsException = 'TooManyRequestsException',
  UserNotConfirmedException = 'UserNotConfirmedException',
  UserNotFoundException = 'UserNotFoundException'
}

export enum ForgotPasswordException {
  CodeDeliveryFailureException = 'CodeDeliveryFailureException',
  ForbiddenException = 'ForbiddenException',
  InternalErrorException = 'InternalErrorException',
  InvalidEmailRoleAccessPolicyException = 'InvalidEmailRoleAccessPolicyException',
  InvalidLambdaResponseException = 'InvalidLambdaResponseException',
  InvalidParameterException = 'InvalidParameterException',
  InvalidSmsRoleAccessPolicyException = 'InvalidSmsRoleAccessPolicyException',
  InvalidSmsRoleTrustRelationshipException = 'InvalidSmsRoleTrustRelationshipException',
  LimitExceededException = 'LimitExceededException',
  NotAuthorizedException = 'NotAuthorizedException',
  ResourceNotFoundException = 'ResourceNotFoundException',
  TooManyRequestsException = 'TooManyRequestsException',
  UnexpectedLambdaException = 'UnexpectedLambdaException',
  UserLambdaValidationException = 'UserLambdaValidationException',
  UserNotFoundException = 'UserNotFoundException'
}

export enum GetUserException {
  ForbiddenException = 'ForbiddenException',
  InternalErrorException = 'InternalErrorException',
  InvalidParameterException = 'InvalidParameterException',
  NotAuthorizedException = 'NotAuthorizedException',
  PasswordResetRequiredException = 'PasswordResetRequiredException',
  ResourceNotFoundException = 'ResourceNotFoundException',
  TooManyRequestsException = 'TooManyRequestsException',
  UserNotConfirmedException = 'UserNotConfirmedException',
  UserNotFoundException = 'UserNotFoundException'
}

export enum GetIdException {
  ExternalServiceException = 'ExternalServiceException',
  InternalErrorException = 'InternalErrorException',
  InvalidParameterException = 'InvalidParameterException',
  LimitExceededException = 'LimitExceededException',
  NotAuthorizedException = 'NotAuthorizedException',
  ResourceConflictException = 'ResourceConflictException',
  ResourceNotFoundException = 'ResourceNotFoundException',
  TooManyRequestsException = 'TooManyRequestsException'
}

export enum GetCredentialsForIdentityException {
  ExternalServiceException = 'ExternalServiceException',
  InternalErrorException = 'InternalErrorException',
  InvalidIdentityPoolConfigurationException = 'InvalidIdentityPoolConfigurationException',
  InvalidParameterException = 'InvalidParameterException',
  NotAuthorizedException = 'NotAuthorizedException',
  ResourceConflictException = 'ResourceConflictException',
  ResourceNotFoundException = 'ResourceNotFoundException',
  TooManyRequestsException = 'TooManyRequestsException'
}

export enum GetUserAttributeVerificationException {
  CodeDeliveryFailureException = 'CodeDeliveryFailureException',
  ForbiddenException = 'ForbiddenException',
  InternalErrorException = 'InternalErrorException',
  InvalidEmailRoleAccessPolicyException = 'InvalidEmailRoleAccessPolicyException',
  InvalidLambdaResponseException = 'InvalidLambdaResponseException',
  InvalidParameterException = 'InvalidParameterException',
  InvalidSmsRoleAccessPolicyException = 'InvalidSmsRoleAccessPolicyException',
  InvalidSmsRoleTrustRelationshipException = 'InvalidSmsRoleTrustRelationshipException',
  LimitExceededException = 'LimitExceededException',
  NotAuthorizedException = 'NotAuthorizedException',
  PasswordResetRequiredException = 'PasswordResetRequiredException',
  ResourceNotFoundException = 'ResourceNotFoundException',
  TooManyRequestsException = 'TooManyRequestsException',
  UnexpectedLambdaException = 'UnexpectedLambdaException',
  UserLambdaValidationException = 'UserLambdaValidationException',
  UserNotConfirmedException = 'UserNotConfirmedException',
  UserNotFoundException = 'UserNotFoundException'
}

export enum GlobalSignOutException {
  ForbiddenException = 'ForbiddenException',
  InternalErrorException = 'InternalErrorException',
  InvalidParameterException = 'InvalidParameterException',
  NotAuthorizedException = 'NotAuthorizedException',
  PasswordResetRequiredException = 'PasswordResetRequiredException',
  ResourceNotFoundException = 'ResourceNotFoundException',
  TooManyRequestsException = 'TooManyRequestsException',
  UserNotConfirmedException = 'UserNotConfirmedException'
}

export enum InitiateAuthException {
  PasswordResetRequiredException = 'PasswordResetRequiredException',
  ForbiddenException = 'ForbiddenException',
  InternalErrorException = 'InternalErrorException',
  InvalidLambdaResponseException = 'InvalidLambdaResponseException',
  InvalidParameterException = 'InvalidParameterException',
  InvalidSmsRoleAccessPolicyException = 'InvalidSmsRoleAccessPolicyException',
  InvalidSmsRoleTrustRelationshipException = 'InvalidSmsRoleTrustRelationshipException',
  InvalidUserPoolConfigurationException = 'InvalidUserPoolConfigurationException',
  NotAuthorizedException = 'NotAuthorizedException',
  ResourceNotFoundException = 'ResourceNotFoundException',
  TooManyRequestsException = 'TooManyRequestsException',
  UnexpectedLambdaException = 'UnexpectedLambdaException',
  UserLambdaValidationException = 'UserLambdaValidationException',
  UserNotConfirmedException = 'UserNotConfirmedException',
  UserNotFoundException = 'UserNotFoundException'
}

export enum ResendConfirmationException {
  CodeDeliveryFailureException = 'CodeDeliveryFailureException',
  ForbiddenException = 'ForbiddenException',
  InternalErrorException = 'InternalErrorException',
  InvalidEmailRoleAccessPolicyException = 'InvalidEmailRoleAccessPolicyException',
  InvalidLambdaResponseException = 'InvalidLambdaResponseException',
  InvalidParameterException = 'InvalidParameterException',
  InvalidSmsRoleAccessPolicyException = 'InvalidSmsRoleAccessPolicyException',
  InvalidSmsRoleTrustRelationshipException = 'InvalidSmsRoleTrustRelationshipException',
  LimitExceededException = 'LimitExceededException',
  NotAuthorizedException = 'NotAuthorizedException',
  ResourceNotFoundException = 'ResourceNotFoundException',
  TooManyRequestsException = 'TooManyRequestsException',
  UnexpectedLambdaException = 'UnexpectedLambdaException',
  UserLambdaValidationException = 'UserLambdaValidationException',
  UserNotFoundException = 'UserNotFoundException'
}

export enum RespondToAuthChallengeException {
  AliasExistsException = 'AliasExistsException',
  CodeMismatchException = 'CodeMismatchException',
  ExpiredCodeException = 'ExpiredCodeException',
  ForbiddenException = 'ForbiddenException',
  InternalErrorException = 'InternalErrorException',
  InvalidLambdaResponseException = 'InvalidLambdaResponseException',
  InvalidParameterException = 'InvalidParameterException',
  InvalidPasswordException = 'InvalidPasswordException',
  InvalidSmsRoleAccessPolicyException = 'InvalidSmsRoleAccessPolicyException',
  InvalidSmsRoleTrustRelationshipException = 'InvalidSmsRoleTrustRelationshipException',
  InvalidUserPoolConfigurationException = 'InvalidUserPoolConfigurationException',
  MFAMethodNotFoundException = 'MFAMethodNotFoundException',
  NotAuthorizedException = 'NotAuthorizedException',
  PasswordResetRequiredException = 'PasswordResetRequiredException',
  ResourceNotFoundException = 'ResourceNotFoundException',
  SoftwareTokenMFANotFoundException = 'SoftwareTokenMFANotFoundException',
  TooManyRequestsException = 'TooManyRequestsException',
  UnexpectedLambdaException = 'UnexpectedLambdaException',
  UserLambdaValidationException = 'UserLambdaValidationException',
  UserNotConfirmedException = 'UserNotConfirmedException',
  UserNotFoundException = 'UserNotFoundException'
}

export enum SetUserMFAPreferenceException {
  ForbiddenException = 'ForbiddenException',
  InternalErrorException = 'InternalErrorException',
  InvalidParameterException = 'InvalidParameterException',
  NotAuthorizedException = 'NotAuthorizedException',
  PasswordResetRequiredException = 'PasswordResetRequiredException',
  ResourceNotFoundException = 'ResourceNotFoundException',
  UserNotConfirmedException = 'UserNotConfirmedException',
  UserNotFoundException = 'UserNotFoundException'
}

export enum SignUpException {
  CodeDeliveryFailureException = 'CodeDeliveryFailureException',
  InternalErrorException = 'InternalErrorException',
  InvalidEmailRoleAccessPolicyException = 'InvalidEmailRoleAccessPolicyException',
  InvalidLambdaResponseException = 'InvalidLambdaResponseException',
  InvalidParameterException = 'InvalidParameterException',
  InvalidPasswordException = 'InvalidPasswordException',
  InvalidSmsRoleAccessPolicyException = 'InvalidSmsRoleAccessPolicyException',
  InvalidSmsRoleTrustRelationshipException = 'InvalidSmsRoleTrustRelationshipException',
  NotAuthorizedException = 'NotAuthorizedException',
  ResourceNotFoundException = 'ResourceNotFoundException',
  TooManyRequestsException = 'TooManyRequestsException',
  UnexpectedLambdaException = 'UnexpectedLambdaException',
  UserLambdaValidationException = 'UserLambdaValidationException',
  UsernameExistsException = 'UsernameExistsException'
}

export enum UpdateUserAttributesException {
  AliasExistsException = 'AliasExistsException',
  CodeDeliveryFailureException = 'CodeDeliveryFailureException',
  CodeMismatchException = 'CodeMismatchException',
  ExpiredCodeException = 'ExpiredCodeException',
  ForbiddenException = 'ForbiddenException',
  InternalErrorException = 'InternalErrorException',
  InvalidEmailRoleAccessPolicyException = 'InvalidEmailRoleAccessPolicyException',
  InvalidLambdaResponseException = 'InvalidLambdaResponseException',
  InvalidParameterException = 'InvalidParameterException',
  InvalidSmsRoleAccessPolicyException = 'InvalidSmsRoleAccessPolicyException',
  InvalidSmsRoleTrustRelationshipException = 'InvalidSmsRoleTrustRelationshipException',
  NotAuthorizedException = 'NotAuthorizedException',
  PasswordResetRequiredException = 'PasswordResetRequiredException',
  ResourceNotFoundException = 'ResourceNotFoundException',
  TooManyRequestsException = 'TooManyRequestsException',
  UnexpectedLambdaException = 'UnexpectedLambdaException',
  UserLambdaValidationException = 'UserLambdaValidationException',
  UserNotConfirmedException = 'UserNotConfirmedException',
  UserNotFoundException = 'UserNotFoundException'
}

export enum VerifySoftwareTokenException {
  CodeMismatchException = 'CodeMismatchException',
  EnableSoftwareTokenMFAException = 'EnableSoftwareTokenMFAException',
  ForbiddenException = 'ForbiddenException',
  InternalErrorException = 'InternalErrorException',
  InvalidParameterException = 'InvalidParameterException',
  InvalidUserPoolConfigurationException = 'InvalidUserPoolConfigurationException',
  NotAuthorizedException = 'NotAuthorizedException',
  PasswordResetRequiredException = 'PasswordResetRequiredException',
  ResourceNotFoundException = 'ResourceNotFoundException',
  SoftwareTokenMFANotFoundException = 'SoftwareTokenMFANotFoundException',
  TooManyRequestsException = 'TooManyRequestsException',
  UserNotConfirmedException = 'UserNotConfirmedException',
  UserNotFoundException = 'UserNotFoundException'
}

export enum VerifyUserAttributeException {
  AliasExistsException = 'AliasExistsException',
  CodeMismatchException = 'CodeMismatchException',
  ExpiredCodeException = 'ExpiredCodeException',
  ForbiddenException = 'ForbiddenException',
  InternalErrorException = 'InternalErrorException',
  InvalidParameterException = 'InvalidParameterException',
  LimitExceededException = 'LimitExceededException',
  NotAuthorizedException = 'NotAuthorizedException',
  PasswordResetRequiredException = 'PasswordResetRequiredException',
  ResourceNotFoundException = 'ResourceNotFoundException',
  TooManyRequestsException = 'TooManyRequestsException',
  UserNotConfirmedException = 'UserNotConfirmedException',
  UserNotFoundException = 'UserNotFoundException'
}

export enum UpdateDeviceStatusException {
  ForbiddenException = 'ForbiddenException',
  InternalErrorException = 'InternalErrorException',
  InvalidParameterException = 'InvalidParameterException',
  InvalidUserPoolConfigurationException = 'InvalidUserPoolConfigurationException',
  NotAuthorizedException = 'NotAuthorizedException',
  PasswordResetRequiredException = 'PasswordResetRequiredException',
  ResourceNotFoundException = 'ResourceNotFoundException',
  TooManyRequestsException = 'TooManyRequestsException',
  UserNotConfirmedException = 'UserNotConfirmedException',
  UserNotFoundException = 'UserNotFoundException'
}

export enum ListDevicesException {
  ForbiddenException = 'ForbiddenException',
  InternalErrorException = 'InternalErrorException',
  InvalidParameterException = 'InvalidParameterException',
  InvalidUserPoolConfigurationException = 'InvalidUserPoolConfigurationException',
  NotAuthorizedException = 'NotAuthorizedException',
  PasswordResetRequiredException = 'PasswordResetRequiredException',
  ResourceNotFoundException = 'ResourceNotFoundException',
  TooManyRequestsException = 'TooManyRequestsException',
  UserNotConfirmedException = 'UserNotConfirmedException',
  UserNotFoundException = 'UserNotFoundException'
}

export enum RevokeTokenException {
  ForbiddenException = 'ForbiddenException',
  InternalErrorException = 'InternalErrorException',
  InvalidParameterException = 'InvalidParameterException',
  TooManyRequestsException = 'TooManyRequestsException',
  UnauthorizedException = 'UnauthorizedException',
  UnsupportedOperationException = 'UnsupportedOperationException',
  UnsupportedTokenTypeException = 'UnsupportedTokenTypeException'
}

export class InitAuthError extends Error {
  constructor(
    message: string,
    public readonly cognitoException: InitiateAuthException
  ) {
    super(message);
  }
}

export class RespondToAuthChallengeError extends Error {
  constructor(
    message: string,
    public readonly cognitoException: RespondToAuthChallengeException
  ) {
    super(message);
  }
}

export class SignUpError extends Error {
  constructor(
    message: string,
    public readonly cognitoException: SignUpException
  ) {
    super(message);
  }
}

export class ConfirmSignUpError extends Error {
  constructor(
    message: string,
    public readonly cognitoException: ConfirmSignUpException
  ) {
    super(message);
  }
}

export class ChangePasswordError extends Error {
  constructor(
    message: string,
    public readonly cognitoException: ChangePasswordException
  ) {
    super(message);
  }
}

export class RevokeTokenError extends Error {
  constructor(
    message: string,
    public readonly cognitoException: RevokeTokenException
  ) {
    super(message);
  }
}

export class ForgotPasswordError extends Error {
  constructor(
    message: string,
    public readonly cognitoException: ForgotPasswordException
  ) {
    super(message);
  }
}

export class ConfirmForgotPasswordError extends Error {
  constructor(
    message: string,
    public readonly cognitoException: ConfirmForgotPasswordException
  ) {
    super(message);
  }
}

export class ResendConfirmationCodeError extends Error {
  constructor(
    message: string,
    public readonly cognitoException: ResendConfirmationException
  ) {
    super(message);
  }
}

export class UpdateUserAttributesError extends Error {
  constructor(
    message: string,
    public readonly cognitoException: UpdateUserAttributesException
  ) {
    super(message);
  }
}

export class VerifyUserAttributeError extends Error {
  constructor(
    message: string,
    public readonly cognitoException: VerifyUserAttributeException
  ) {
    super(message);
  }
}

export class GlobalSignOutError extends Error {
  constructor(
    message: string,
    public readonly cognitoException: GlobalSignOutException
  ) {
    super(message);
  }
}
