import { withPageAuthRequired, withApiAuthRequired } from '../src';

describe('index', () => {
  test('withPageAuthRequired should not create an SDK instance at build time', () => {
    expect(process.env).not.toContain('AUTH0_SECRET');
    expect(() => withApiAuthRequired(jest.fn())).toThrow('"secret" is required');
    expect(() => withPageAuthRequired()).not.toThrow();
  });
});
