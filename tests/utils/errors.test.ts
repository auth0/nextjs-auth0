import { AccessTokenError, AccessTokenErrorCode, HandlerError } from '../../src/utils/errors';

describe('errors', () => {
  test('should be instance of themselves', () => {
    expect(new AccessTokenError(AccessTokenErrorCode.MISSING_SESSION, 'message')).toBeInstanceOf(AccessTokenError);
    expect(new HandlerError(new Error('message'))).toBeInstanceOf(HandlerError);
  });
});
