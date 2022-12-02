import {
  AccessTokenError,
  AccessTokenErrorCode,
  appendCause,
  AuthError,
  CallbackHandlerError,
  HandlerError,
  LoginHandlerError,
  LogoutHandlerError,
  ProfileHandlerError
} from '../../src/utils/errors';

describe('appendCause', () => {
  test('should append the cause error message', () => {
    const message = 'foo';
    const cause = new Error('bar');

    expect(appendCause(message, cause)).toEqual(`${message}. CAUSE: ${cause.message}`);
  });

  test('should not add a period if there is one already', () => {
    const message = 'foo.';
    const cause = new Error('bar');

    expect(appendCause(message, cause)).toEqual(`${message} CAUSE: ${cause.message}`);
  });

  test('should return the error message when there is no cause', () => {
    const message = 'foo';

    expect(appendCause(message, undefined)).toEqual(message);
  });
});

describe('AccessTokenError', () => {
  test('should be instance of itself', () => {
    expect(new AccessTokenError(AccessTokenErrorCode.MISSING_SESSION, '')).toBeInstanceOf(AccessTokenError);
  });

  test('should be instance of AuthError', () => {
    expect(new AccessTokenError(AccessTokenErrorCode.MISSING_SESSION, '')).toBeInstanceOf(AuthError);
  });

  test('should set all properties', () => {
    const message = 'foo';
    const error = new AccessTokenError(AccessTokenErrorCode.MISSING_ACCESS_TOKEN, message);

    expect(error.code).toEqual(AccessTokenErrorCode.MISSING_ACCESS_TOKEN);
    expect(error.message).toEqual(message);
    expect(error.name).toEqual('AccessTokenError');
    expect(error.cause).toBeUndefined();
    expect(error.status).toBeUndefined();
  });
});

describe('HandlerError', () => {
  test('should not be instance of itself', () => {
    expect(new HandlerError({ code: '', message: '', name: '', cause: new Error() })).not.toBeInstanceOf(HandlerError);
  });

  test('should set all required properties', () => {
    const code = 'foo';
    const message = 'bar';
    const name = 'baz';
    const cause = new Error('qux');
    const error = new HandlerError({ code, message, name, cause });

    expect(error.code).toEqual(code);
    expect(error.message).toEqual(`${message}. CAUSE: ${cause.message}`);
    expect(error.name).toEqual(name);
    expect(error.cause).toEqual(cause);
    expect(error.status).toBeUndefined();
  });

  test('should set status', () => {
    const cause: Error & { status?: number } = new Error();
    cause.status = 400;
    const error = new HandlerError({ code: '', message: '', name: '', cause });

    expect(error.cause).toEqual(cause);
    expect(error.status).toEqual(cause.status);
  });
});

describe('CallbackHandlerError', () => {
  test('should be instance of itself', () => {
    expect(new CallbackHandlerError(new Error())).toBeInstanceOf(CallbackHandlerError);
  });

  test('should be instance of HandlerError', () => {
    expect(new CallbackHandlerError(new Error())).toBeInstanceOf(HandlerError);
  });

  test('should be instance of AuthError', () => {
    expect(new CallbackHandlerError(new Error())).toBeInstanceOf(AuthError);
  });

  test('should set all properties', () => {
    const cause = new Error('foo');
    const error = new CallbackHandlerError(cause);

    expect(error.code).toEqual(CallbackHandlerError.code);
    expect(error.message).toEqual(`Callback handler failed. CAUSE: ${cause.message}`);
    expect(error.name).toEqual('CallbackHandlerError');
    expect(error.cause).toEqual(cause);
    expect(error.status).toBeUndefined();
  });
});

describe('LoginHandlerError', () => {
  test('should be instance of itself', () => {
    expect(new LoginHandlerError(new Error())).toBeInstanceOf(LoginHandlerError);
  });

  test('should be instance of HandlerError', () => {
    expect(new LoginHandlerError(new Error())).toBeInstanceOf(HandlerError);
  });

  test('should be instance of AuthError', () => {
    expect(new LoginHandlerError(new Error())).toBeInstanceOf(AuthError);
  });

  test('should set all properties', () => {
    const cause = new Error('foo');
    const error = new LoginHandlerError(cause);

    expect(error.code).toEqual(LoginHandlerError.code);
    expect(error.message).toEqual(`Login handler failed. CAUSE: ${cause.message}`);
    expect(error.name).toEqual('LoginHandlerError');
    expect(error.cause).toEqual(cause);
    expect(error.status).toBeUndefined();
  });
});

describe('LogoutHandlerError', () => {
  test('should be instance of itself', () => {
    expect(new LogoutHandlerError(new Error())).toBeInstanceOf(LogoutHandlerError);
  });

  test('should be instance of HandlerError', () => {
    expect(new LogoutHandlerError(new Error())).toBeInstanceOf(HandlerError);
  });

  test('should be instance of AuthError', () => {
    expect(new LogoutHandlerError(new Error())).toBeInstanceOf(AuthError);
  });

  test('should set all properties', () => {
    const cause = new Error('foo');
    const error = new LogoutHandlerError(cause);

    expect(error.code).toEqual(LogoutHandlerError.code);
    expect(error.message).toEqual(`Logout handler failed. CAUSE: ${cause.message}`);
    expect(error.name).toEqual('LogoutHandlerError');
    expect(error.cause).toEqual(cause);
    expect(error.status).toBeUndefined();
  });
});

describe('ProfileHandlerError', () => {
  test('should be instance of itself', () => {
    expect(new ProfileHandlerError(new Error())).toBeInstanceOf(ProfileHandlerError);
  });

  test('should be instance of HandlerError', () => {
    expect(new ProfileHandlerError(new Error())).toBeInstanceOf(HandlerError);
  });

  test('should be instance of AuthError', () => {
    expect(new ProfileHandlerError(new Error())).toBeInstanceOf(AuthError);
  });

  test('should set all properties', () => {
    const cause = new Error('foo');
    const error = new ProfileHandlerError(cause);

    expect(error.code).toEqual(ProfileHandlerError.code);
    expect(error.message).toEqual(`Profile handler failed. CAUSE: ${cause.message}`);
    expect(error.name).toEqual('ProfileHandlerError');
    expect(error.cause).toEqual(cause);
    expect(error.status).toBeUndefined();
  });
});
