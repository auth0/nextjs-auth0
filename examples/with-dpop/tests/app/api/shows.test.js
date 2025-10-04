/**
 * @jest-environment node
 */
import { vi } from 'vitest';
import { GET as shows } from '../../../app/api/shows/route';

const req = vi.fn();
const res = (() => {
  const mock = {};
  mock.status = vi.fn().mockReturnValue(mock);
  mock.json = vi.fn().mockReturnValue(mock);
  return mock;
})();

describe('/api/shows', () => {
  afterAll(() => {
    delete global.fetch;
  });

  it('should call the external API', async () => {
    global.fetch = vi.fn().mockReturnValue({ json: () => Promise.resolve({ msg: 'Text' }) });

    const res = await shows(req);

    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toEqual({ msg: 'Text' });
  });

  it('should fail when the external API call fails', async () => {
    global.fetch = vi.fn().mockReturnValue({ json: () => Promise.reject(new Error('Error')) });

    const res = await shows(req);

    expect(res.status).toBe(500);
    await expect(res.json()).resolves.toEqual({ error: 'Error' });
  });
});
