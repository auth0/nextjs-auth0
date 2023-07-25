import { AddressInfo } from 'net';
import { createServer, get as getRequest, IncomingMessage, ServerResponse } from 'http';
import { NodeResponse } from '../../../src/auth0-session/http';

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

describe('NodeResponse', () => {
  it('should set a cookie', async () => {
    const [, res, teardown] = await setup();
    const setter = new NodeResponse(res);
    setter.setCookie('foo', 'bar');
    expect(res.getHeader('Set-Cookie')).toEqual(['foo=bar']);
    await teardown();
  });

  it('should set a cookie with opts', async () => {
    const [, res, teardown] = await setup();
    const setter = new NodeResponse(res);
    setter.setCookie('foo', 'bar', { httpOnly: true, sameSite: 'strict' });
    expect(res.getHeader('Set-Cookie')).toEqual(['foo=bar; HttpOnly; SameSite=Strict']);
    await teardown();
  });

  it('should not overwrite existing set cookie', async () => {
    const [, res, teardown] = await setup();
    res.setHeader('Set-Cookie', 'foo=bar');
    const setter = new NodeResponse(res);
    setter.setCookie('baz', 'qux');
    expect(res.getHeader('Set-Cookie')).toEqual(['foo=bar', 'baz=qux']);
    await teardown();
  });

  it('should clear cookies', async () => {
    const [, res, teardown] = await setup();
    const setter = new NodeResponse(res);
    setter.clearCookie('foo');
    expect(res.getHeader('Set-Cookie')).toEqual(['foo=; Max-Age=0']);
    await teardown();
  });
});
