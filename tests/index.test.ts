import { withAuth0 } from '../src';

describe('withAuth0', () => {
  test('should be exported correctly in node', async () => {
    expect(withAuth0).toBeInstanceOf(Function);
  });
});
