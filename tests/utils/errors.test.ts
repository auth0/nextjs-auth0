import {
  AccessTokenError,
  AccessTokenErrorCode,
  AuthError,
  CallbackHandlerError,
  HandlerError,
  LoginHandlerError,
  LogoutHandlerError,
  ProfileHandlerError
} from '../../src/utils/errors';

describe('errors', () => {
  test('should be instance of themselves', () => {
    expect(new AccessTokenError(AccessTokenErrorCode.MISSING_SESSION, '')).toBeInstanceOf(AccessTokenError);
    expect(new CallbackHandlerError(new Error(''))).toBeInstanceOf(CallbackHandlerError);
    expect(new LoginHandlerError(new Error(''))).toBeInstanceOf(LoginHandlerError);
    expect(new LogoutHandlerError(new Error(''))).toBeInstanceOf(LogoutHandlerError);
    expect(new ProfileHandlerError(new Error(''))).toBeInstanceOf(ProfileHandlerError);
  });

  test('should be instance of AuthError', () => {
    expect(new AccessTokenError(AccessTokenErrorCode.MISSING_SESSION, '')).toBeInstanceOf(AuthError);
    expect(new CallbackHandlerError(new Error(''))).toBeInstanceOf(AuthError);
    expect(new LoginHandlerError(new Error(''))).toBeInstanceOf(AuthError);
    expect(new LogoutHandlerError(new Error(''))).toBeInstanceOf(AuthError);
    expect(new ProfileHandlerError(new Error(''))).toBeInstanceOf(AuthError);
  });

  test('should be instance of HandlerError', () => {
    expect(new CallbackHandlerError(new Error(''))).toBeInstanceOf(HandlerError);
    expect(new LoginHandlerError(new Error(''))).toBeInstanceOf(HandlerError);
    expect(new LogoutHandlerError(new Error(''))).toBeInstanceOf(HandlerError);
    expect(new ProfileHandlerError(new Error(''))).toBeInstanceOf(HandlerError);
  });
});
