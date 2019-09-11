import request from 'request';
import { parse } from 'cookie';
import { promisify } from 'util';

import HttpServer from '../helpers/server';
import logout from '../../src/handlers/logout';
import { withoutApi } from '../helpers/default-settings';
import CookieSessionStoreSettings from '../../src/session/cookie-store/settings';

const [getAsync] = [request.get].map(promisify);

describe('logout handler', () => {
  let httpServer: HttpServer;

  beforeAll((done) => {
    httpServer = new HttpServer(logout(withoutApi, new CookieSessionStoreSettings(withoutApi.session)));
    httpServer.start(done);
  });

  afterAll((done) => {
    httpServer.stop(done);
  });

  test('should redirect to the identity provider', async () => {
    const { statusCode, headers } = await getAsync({
      url: httpServer.getUrl(),
      followRedirect: false
    });

    expect(statusCode).toBe(302);
    expect(headers.location)
      .toBe(`https://${withoutApi.domain}/v2/logout?client_id=${withoutApi.clientId}&returnTo=https%3A%2F%2Fwww.acme.com`);
  });

  test('should delete the state and session', async () => {
    const { headers } = await getAsync({
      url: httpServer.getUrl(),
      headers: {
        cookie: ['a0:state=foo', 'a0:session=bar'].join('; ')
      },
      followRedirect: false
    });

    const [stateCookie, sessionCookie] = headers['set-cookie'];
    expect(parse(stateCookie)).toMatchObject({
      'a0:state': '',
      'Max-Age': '-1'
    });
    expect(parse(sessionCookie)).toMatchObject({
      'a0:session': '',
      'Max-Age': '-1'
    });
  });
});
