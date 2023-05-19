import { AddressInfo } from 'net';
import { createServer, get as getRequest, IncomingMessage, ServerResponse } from 'http';
import { NodeRequest } from '../../../src/auth0-session/http';

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

describe('NodeRequest', () => {
  it('should get all cookies', async () => {
    const [req, , teardown] = await setup();
    req.headers.cookie = 'foo=bar; bar=baz;';
    expect(new NodeRequest(req).getCookies()).toMatchObject({ foo: 'bar', bar: 'baz' });
    await teardown();
  });

  it('should get a cookie by name', async () => {
    const [req, , teardown] = await setup();
    req.headers.cookie = 'foo=bar; bar=baz;';
    expect(new NodeRequest(req).getCookies()['foo']).toEqual('bar');
    await teardown();
  });
});
