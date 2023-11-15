/**
 * Possible Cognito exceptions
 */
export enum CognitoException {
  /**
   * You do not have sufficient access to perform this action.
   */
  AccessDeniedException = "AccessDeniedException",

  /**
   * The request signature does not conform to AWS standards.
   */
  IncompleteSignature = "IncompleteSignature",

  /**
   * The request processing has failed because of an unknown error, exception or failure.
   */
  InternalFailure = "InternalFailure",

  /**
   * The action or operation requested is invalid. Verify that the action is typed correctly.
   */
  InvalidAction = "InvalidAction",

  /**
   * The X.509 certificate or AWS access key ID provided does not exist in our records.
   */
  InvalidClientTokenId = "InvalidClientTokenId",

  /**
   * You do not have permission to perform this action.
   */
  NotAuthorized = "NotAuthorized",

  /**
   * The AWS access key ID needs a subscription for the service.
   */
  OptInRequired = "OptInRequired",

  /**
   * The request reached the service more than 15 minutes after the date stamp on the request or more than 15 minutes after the request expiration date (such as for pre-signed URLs), or the date stamp on the request is more than 15 minutes in the future.
   */
  RequestExpired = "RequestExpired",

  /**
   * The request has failed due to a temporary failure of the server.
   */
  ServiceUnavailable = "ServiceUnavailable",

  /**
   * The request was denied due to request throttling.
   */
  ThrottlingException = "ThrottlingException",

  /**
   * The input fails to satisfy the constraints specified by an AWS service.
   */
  ValidationError = "ValidationError",

  /**
   * This exception is thrown when AWS WAF doesn't allow your request based on a web ACL that's associated with your user pool.
   */
  ForbiddenException = "ForbiddenException",

  /**
   * This exception is thrown when Amazon Cognito encounters an internal error.
   */
  InternalErrorException = "InternalErrorException",

  /**
   * This exception is thrown when Amazon Cognito encounters an invalid AWS Lambda response.
   */
  InvalidLambdaResponseException = "InvalidLambdaResponseException",

  /**
   * This exception is thrown when the Amazon Cognito service encounters an invalid parameter.
   */
  InvalidParameterException = "InvalidParameterException",

  /**
   * This exception is returned when the role provided for SMS configuration doesn't have permission to publish using Amazon SNS.
   */
  InvalidSmsRoleAccessPolicyException = "InvalidSmsRoleAccessPolicyException",

  /**
   * This exception is thrown when the trust relationship is not valid for the role provided for SMS configuration. This can happen if you don't trust cognito-idp.amazonaws.com or the external ID provided in the role does not match what is provided in the SMS configuration for the user pool.
   */

  InvalidSmsRoleTrustRelationshipException = "InvalidSmsRoleTrustRelationshipException",

  /**
   * This exception is thrown when the user pool configuration is not valid.
   */
  InvalidUserPoolConfigurationException = "InvalidUserPoolConfigurationException",

  /**
   * This exception is thrown when a user isn't authorized.
   */
  NotAuthorizedException = "NotAuthorizedException",

  /**
   * This exception is thrown when a password reset is required.
   */
  PasswordResetRequiredException = "PasswordResetRequiredException",

  /**
   * This exception is thrown when the Amazon Cognito service can't find the requested resource.
   */
  ResourceNotFoundException = "ResourceNotFoundException",

  /**
   * This exception is thrown when the user has made too many requests for a given operation.
   */
  TooManyRequestsException = "TooManyRequestsException",

  /**
   * This exception is thrown when Amazon Cognito encounters an unexpected exception with AWS Lambda.
   */
  UnexpectedLambdaException = "UnexpectedLambdaException",

  /**
   * This exception is thrown when the Amazon Cognito service encounters a user validation exception with the AWS Lambda service.
   */
  UserLambdaValidationException = "UserLambdaValidationException",

  /**
   * This exception is thrown when a user isn't confirmed successfully.
   */
  UserNotConfirmedException = "UserNotConfirmedException",

  /**
   * This exception is thrown when a user isn't found.
   */
  UserNotFoundException = "UserNotFoundException",

  /**
   * Unknown auth error happened.
   */
  Unknown = "unknown",
}

export class CognitoError extends Error {
  public readonly authError: CognitoException;

  constructor(message: string, authError: CognitoException) {
    super(message);
    this.authError = authError;
  }
}
