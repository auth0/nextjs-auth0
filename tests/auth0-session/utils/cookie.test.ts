import { AddressInfo } from 'net';
import { createServer, get as getRequest, IncomingMessage, ServerResponse } from 'http';
import Cookies from '../../../src/auth0-session/utils/cookies';

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
    expect(new Cookies().getAll(req)).toMatchObject({ foo: 'bar', bar: 'baz' });
    await teardown();
  });

  it('should get a cookie by name', async () => {
    const [req, , teardown] = await setup();
    req.headers.cookie = 'foo=bar; bar=baz;';
    expect(new Cookies().getAll(req)['foo']).toEqual('bar');
    await teardown();
  });

  it('should set a cookie', async () => {
    const [, res, teardown] = await setup();
    const setter = new Cookies();
    setter.set('foo', 'bar');
    setter.commit(res);
    expect(res.getHeader('Set-Cookie')).toEqual(['foo=bar']);
    await teardown();
  });

  it('should set a cookie with opts', async () => {
    const [, res, teardown] = await setup();
    const setter = new Cookies();
    setter.set('foo', 'bar', { httpOnly: true, sameSite: 'strict' });
    setter.commit(res);
    expect(res.getHeader('Set-Cookie')).toEqual(['foo=bar; HttpOnly; SameSite=Strict']);
    await teardown();
  });

  it('should not overwrite existing set cookie', async () => {
    const [, res, teardown] = await setup();
    res.setHeader('Set-Cookie', 'foo=bar');
    const setter = new Cookies();
    setter.set('baz', 'qux');
    setter.commit(res);
    expect(res.getHeader('Set-Cookie')).toEqual(['foo=bar', 'baz=qux']);
    await teardown();
  });

  it('should override existing cookies that equal name', async () => {
    const [, res, teardown] = await setup();
    res.setHeader('Set-Cookie', ['foo=bar', 'baz=qux']);
    const setter = new Cookies();
    setter.set('foo', 'qux');
    setter.commit(res, 'foo');
    expect(res.getHeader('Set-Cookie')).toEqual(['baz=qux', 'foo=qux']);
    await teardown();
  });

  it('should override existing cookies that match name', async () => {
    const [, res, teardown] = await setup();
    res.setHeader('Set-Cookie', ['foo.1=bar', 'foo.2=baz']);
    const setter = new Cookies();
    setter.set('foo', 'qux');
    setter.commit(res, 'foo');
    expect(res.getHeader('Set-Cookie')).toEqual(['foo=qux']);
    await teardown();
  });

  it('should clear cookies', async () => {
    const [, res, teardown] = await setup();
    const setter = new Cookies();
    setter.clear('foo');
    setter.commit(res);
    expect(res.getHeader('Set-Cookie')).toEqual(['foo=; Max-Age=0']);
    await teardown();
  });
});
