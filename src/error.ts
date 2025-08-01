export enum CommonException {
  AccessDeniedException = 'AccessDeniedException',
  IncompleteSignature = 'IncompleteSignature',
  InternalFailure = 'InternalFailure',
  InvalidAction = 'InvalidAction',
  InvalidClientTokenId = 'InvalidClientTokenId',
  NotAuthorized = 'NotAuthorized',
  OptInRequired = 'OptInRequired',
  RequestExpired = 'RequestExpired',
  ServiceUnavailable = 'ServiceUnavailable',
  ThrottlingException = 'ThrottlingException',
  ValidationError = 'ValidationError'
}

export const COMMON_EXCEPTIONS = [
  CommonException.AccessDeniedException,
  CommonException.IncompleteSignature,
  CommonException.InternalFailure,
  CommonException.InvalidAction,
  CommonException.InvalidClientTokenId,
  CommonException.NotAuthorized,
  CommonException.OptInRequired,
  CommonException.RequestExpired,
  CommonException.ServiceUnavailable,
  CommonException.ThrottlingException,
  CommonException.ValidationError
];

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

export type CognitoErrorType =
  | 'CommonError'
  | 'InitAuthError'
  | 'RespondToAuthChallengeError'
  | 'SignUpError'
  | 'ConfirmSignUpError'
  | 'VerifySoftwareTokenError'
  | 'ChangePasswordError'
  | 'RevokeTokenError'
  | 'ForgotPasswordError'
  | 'ConfirmForgotPasswordError'
  | 'ResendConfirmationCodeError'
  | 'UpdateUserAttributesError'
  | 'VerifyUserAttributeError'
  | 'AssociateSoftwareTokenError'
  | 'GlobalSignOutError'
  | 'SetUserMFAPreferenceError'
  | 'GetUserError'
  | 'ListDevicesError';

export class CognitoError extends Error {
  constructor(
    message: string,
    public readonly errorType: CognitoErrorType,
    public readonly cognitoException:
      | CommonException
      | InitiateAuthException
      | RespondToAuthChallengeException
      | SignUpException
      | ConfirmSignUpException
      | ChangePasswordException
      | RevokeTokenException
      | ForgotPasswordException
      | ConfirmForgotPasswordException
      | ResendConfirmationException
      | UpdateUserAttributesException
      | VerifyUserAttributeException
      | GlobalSignOutException
      | VerifySoftwareTokenException
      | AssociateSoftwareTokenException
      | SetUserMFAPreferenceException
      | ListDevicesException
      | GetUserException
  ) {
    super(message);
  }
}

export class CommonError extends CognitoError {
  constructor(
    message: string,
    public readonly cognitoException: CommonException
  ) {
    super(message, 'CommonError', cognitoException);
  }
}

export class InitAuthError extends CognitoError {
  constructor(
    message: string,
    public readonly cognitoException: InitiateAuthException
  ) {
    super(message, 'InitAuthError', cognitoException);
  }
}

export class RespondToAuthChallengeError extends CognitoError {
  constructor(
    message: string,
    public readonly cognitoException: RespondToAuthChallengeException
  ) {
    super(message, 'RespondToAuthChallengeError', cognitoException);
  }
}

export class SignUpError extends CognitoError {
  constructor(
    message: string,
    public readonly cognitoException: SignUpException
  ) {
    super(message, 'SignUpError', cognitoException);
  }
}

export class ConfirmSignUpError extends CognitoError {
  constructor(
    message: string,
    public readonly cognitoException: ConfirmSignUpException
  ) {
    super(message, 'ConfirmSignUpError', cognitoException);
  }
}

export class ChangePasswordError extends CognitoError {
  constructor(
    message: string,
    public readonly cognitoException: ChangePasswordException
  ) {
    super(message, 'ChangePasswordError', cognitoException);
  }
}

export class RevokeTokenError extends CognitoError {
  constructor(
    message: string,
    public readonly cognitoException: RevokeTokenException
  ) {
    super(message, 'RevokeTokenError', cognitoException);
  }
}

export class ForgotPasswordError extends CognitoError {
  constructor(
    message: string,
    public readonly cognitoException: ForgotPasswordException
  ) {
    super(message, 'ForgotPasswordError', cognitoException);
  }
}

export class ConfirmForgotPasswordError extends CognitoError {
  constructor(
    message: string,
    public readonly cognitoException: ConfirmForgotPasswordException
  ) {
    super(message, 'ConfirmForgotPasswordError', cognitoException);
  }
}

export class ResendConfirmationCodeError extends CognitoError {
  constructor(
    message: string,
    public readonly cognitoException: ResendConfirmationException
  ) {
    super(message, 'ResendConfirmationCodeError', cognitoException);
  }
}

export class UpdateUserAttributesError extends CognitoError {
  constructor(
    message: string,
    public readonly cognitoException: UpdateUserAttributesException
  ) {
    super(message, 'UpdateUserAttributesError', cognitoException);
  }
}

export class VerifyUserAttributeError extends CognitoError {
  constructor(
    message: string,
    public readonly cognitoException: VerifyUserAttributeException
  ) {
    super(message, 'VerifyUserAttributeError', cognitoException);
  }
}

export class GlobalSignOutError extends CognitoError {
  constructor(
    message: string,
    public readonly cognitoException: GlobalSignOutException
  ) {
    super(message, 'GlobalSignOutError', cognitoException);
  }
}

export class VerifySoftwareTokenError extends CognitoError {
  constructor(
    message: string,
    public readonly cognitoException: VerifySoftwareTokenException
  ) {
    super(message, 'VerifySoftwareTokenError', cognitoException);
  }
}

export class AssociateSoftwareTokenError extends CognitoError {
  constructor(
    message: string,
    public readonly cognitoException: AssociateSoftwareTokenException
  ) {
    super(message, 'AssociateSoftwareTokenError', cognitoException);
  }
}

export class SetUserMFAPreferenceError extends CognitoError {
  constructor(
    message: string,
    public readonly cognitoException: SetUserMFAPreferenceException
  ) {
    super(message, 'SetUserMFAPreferenceError', cognitoException);
  }
}
export class ListDevicesError extends CognitoError {
  constructor(
    message: string,
    public readonly cognitoException: ListDevicesException
  ) {
    super(message, 'ListDevicesError', cognitoException);
  }
}

export class GetUserError extends CognitoError {
  constructor(
    message: string,
    public readonly cognitoException: GetUserException
  ) {
    super(message, 'GetUserError', cognitoException);
  }
}
