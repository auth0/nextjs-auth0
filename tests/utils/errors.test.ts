import { AccessTokenError, HandlerError } from '../../src/utils/errors';

describe('errors', () => {
  test('should be instance of themselves', () => {
    expect(new AccessTokenError('code', 'message')).toBeInstanceOf(AccessTokenError);
    expect(new HandlerError(new Error('message'))).toBeInstanceOf(HandlerError);
  });
});
