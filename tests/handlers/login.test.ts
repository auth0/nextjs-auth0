import request from 'request';
import { parse } from 'cookie';
import { promisify } from 'util';

import login from '../../src/handlers/login';
import getClient from '../../src/utils/oidc-client';

import HttpServer from '../helpers/server';
import { discovery } from '../helpers/oidc-nocks';
import { withoutApi } from '../helpers/default-settings';

const [getAsync] = [request.get].map(promisify);

describe('login handler', () => {
  let httpServer: HttpServer;

  beforeAll((done) => {
    discovery(withoutApi);
    httpServer = new HttpServer(login(withoutApi, getClient(withoutApi)));
    httpServer.start(done);
  });

  afterAll((done) => {
    httpServer.stop(done);
  });

  test('should create a state', async () => {
    const { headers } = await getAsync({
      url: httpServer.getUrl(),
      followRedirect: false
    });

    const state = parse(headers['set-cookie'][0]);
    expect(state).toBeTruthy();
  });

  test('should redirect to the identity provider', async () => {
    const { statusCode, headers } = await getAsync({
      url: httpServer.getUrl(),
      followRedirect: false
    });

    expect(statusCode).toBe(302);

    const state = parse(headers['set-cookie'][0]);
    expect(headers.location)
      .toContain(`https://${withoutApi.domain}/authorize?`
        + `client_id=${withoutApi.clientId}&scope=${encodeURIComponent(withoutApi.scope)}`
        + `&response_type=code&redirect_uri=${encodeURIComponent(withoutApi.redirectUri)}`
        + `&state=${state['a0:state']}`);
  });
});
