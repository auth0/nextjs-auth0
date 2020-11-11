import { AddressInfo } from 'net';
import { createServer, get as getRequest, IncomingMessage, ServerResponse } from 'http';
import { getAll, get, set, clear } from '../../../src/auth0-session/utils/cookies';

const setup = (): Promise<[IncomingMessage, ServerResponse, Function]> =>
  new Promise((resolve) => {
    const server = createServer((req, res) => {
      resolve([
        req,
        res,
        (): Promise<void> =>
          new Promise((resolve) => {
            res.end();
            server.close(resolve as (err?: Error) => void);
          })
      ]);
    });
    server.listen(0, () => {
      const url = `http://localhost:${(server.address() as AddressInfo).port}`;
      getRequest(url);
    });
  });

describe('cookie', () => {
  it('should get all cookies', async () => {
    const [req, , teardown] = await setup();
    req.headers.cookie = 'foo=bar; bar=baz;';
    expect(getAll(req)).toMatchObject({ foo: 'bar', bar: 'baz' });
    await teardown();
  });

  it('should get a cookie by name', async () => {
    const [req, , teardown] = await setup();
    req.headers.cookie = 'foo=bar; bar=baz;';
    expect(get(req, 'foo')).toEqual('bar');
    await teardown();
  });

  it('should set a cookie', async () => {
    const [, res, teardown] = await setup();
    set(res, 'foo', 'bar');
    expect(res.getHeader('Set-Cookie')).toEqual(['foo=bar']);
    await teardown();
  });

  it('should set a cookie with opts', async () => {
    const [, res, teardown] = await setup();
    set(res, 'foo', 'bar', { httpOnly: true, sameSite: 'strict' });
    expect(res.getHeader('Set-Cookie')).toEqual(['foo=bar; HttpOnly; SameSite=Strict']);
    await teardown();
  });

  it('should not overwrite existing set cookie', async () => {
    const [, res, teardown] = await setup();
    res.setHeader('Set-Cookie', 'foo=bar');
    set(res, 'baz', 'qux');
    expect(res.getHeader('Set-Cookie')).toEqual(['foo=bar', 'baz=qux']);
    await teardown();
  });

  it('should not overwrite existing set cookie array', async () => {
    const [, res, teardown] = await setup();
    set(res, 'foo', 'bar');
    set(res, 'baz', 'qux');
    expect(res.getHeader('Set-Cookie')).toEqual(['foo=bar', 'baz=qux']);
    await teardown();
  });

  it('should clear cookies', async () => {
    const [, res, teardown] = await setup();
    clear(res, 'foo');
    expect(res.getHeader('Set-Cookie')).toEqual(['foo=; Max-Age=0']);
    await teardown();
  });
});
