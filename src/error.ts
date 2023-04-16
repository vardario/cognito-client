/**
 * Possible Authentications errors
 */
export enum AuthError {
  /**
   * User already confirmed
   */
  UserConfirmedAlready = 'user_confirmed_already',

  /**
   * User Profile does not exists.
   */
  UserDoesNotExist = 'user_does_not_exist',

  /**
   * User Profile does not exists.
   */
  UserAlreadyExists = 'user_already_exists',

  /**
   * Password was wrong.
   */
  EmailOrPasswordWrong = 'email_or_password_wrong',

  /**
   * Rate limit exceeded.
   */
  LimitExceededException = 'limit_exceeded_exception',

  /**
   * User needs to be authenticated.
   */
  UserNotAuthenticated = 'user_not_authenticated',

  /**
   * The user tried to many times wiht the wrong password
   */
  PasswordAttempsExceeded = 'password_attemps_exceeded',

  /**
   * User E-Mail needs to be verified.
   */
  UserEmailNotVerified = 'user_email_not_verified',

  /**
   * Unknown auth error happened.
   */
  Unknown = 'unknown',
}

export class AuthException extends Error {
  public readonly authError: AuthError;

  constructor(message: string, authError: AuthError) {
    super(message);
    this.authError = authError;
  }
}

export enum ErrorCode {
  UserNotFoundException = 'UserNotFoundException',
  NotAuthorizedException = 'NotAuthorizedException',
  LimitExceededException = 'LimitExceededException',
}

export interface CognitoAuthErrorResponse {
  __type: ErrorCode;
  message: string;
}

export function getAuthError(errorResponse: CognitoAuthErrorResponse) {
  const mapping: Record<string, AuthError> = {
    'UserNotFoundException:User cannot be confirmed. Current status is CONFIRMED': AuthError.UserConfirmedAlready,
    'NotAuthorizedException:Incorrect username or password.': AuthError.EmailOrPasswordWrong,
    'LimitExceededException:Attempt limit exceeded, please try after some time.': AuthError.LimitExceededException,
    'UserNotFoundException:Username/client id combination not found.': AuthError.UserDoesNotExist,
    'UserNotFoundException:User does not exist.': AuthError.UserDoesNotExist,
    'NotAuthorizedException:Password attempts exceeded': AuthError.PasswordAttempsExceeded,
    'UsernameExistsException:An account with the given email already exists.': AuthError.UserAlreadyExists,
    'InvalidParameterException:Cannot reset password for the user as there is no registered/verified email or phone_number':
      AuthError.UserEmailNotVerified,
    'UserNotConfirmedException:User is not confirmed.': AuthError.UserEmailNotVerified,
  };

  const message = `${errorResponse.__type}:${errorResponse.message}`;
  const authError = mapping[message] || AuthError.Unknown;

  return new AuthException(message, authError);
}
