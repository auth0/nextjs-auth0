import getClient from '../../src/utils/oidc-client';

import { withoutApi } from '../helpers/default-settings';
import { discovery, userInfoWithDelay } from '../helpers/oidc-nocks';

describe('oidc client', () => {
  test('should not timeout for fast requests', async () => {
    discovery(withoutApi);
    userInfoWithDelay(withoutApi, 500);

    const clientFactory = getClient({
      ...withoutApi
    });

    const client = await clientFactory();
    const userInfo = await client.userinfo('foo');
    expect(userInfo).toStrictEqual({});
  });

  test('should timeout for slow requests', async () => {
    discovery(withoutApi);
    userInfoWithDelay(withoutApi, 2600);

    const clientFactory = getClient({
      ...withoutApi
    });

    const client = await clientFactory();
    return expect(client.userinfo('foo')).rejects.toEqual(
      new Error('Timeout awaiting \'request\' for 2500ms')
    );
  });

  test('should allow overriding the request timeout slow requests', async () => {
    discovery(withoutApi);
    userInfoWithDelay(withoutApi, 2600);

    const clientFactory = getClient({
      ...withoutApi,
      httpClient: {
        timeout: 3000
      }
    });

    const client = await clientFactory();
    expect(await client.userinfo('foo')).toStrictEqual({});
  });
});
