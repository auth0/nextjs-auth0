import { withPageAuthRequired, withApiAuthRequired } from '../src';

describe('index', () => {
  test('withPageAuthRequired should not create an SDK instance at build time', () => {
    const secret = process.env.AUTH0_SECRET;
    delete process.env.AUTH0_SECRET;
    expect(() => withApiAuthRequired(jest.fn())).toThrow('"secret" is required');
    expect(() => withPageAuthRequired()).not.toThrow();
    process.env.AUTH0_SECRET = secret;
  });
});
