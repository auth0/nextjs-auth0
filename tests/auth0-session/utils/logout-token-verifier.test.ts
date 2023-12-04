import { makeLogoutToken, jwks } from '../fixtures/cert';
import { getConfig } from '../../../src/auth0-session';
import getLogoutTokenVerifier, { VerifyLogoutToken } from '../../../src/auth0-session/utils/logout-token-verifier';
import { withApi } from '../../fixtures/default-settings';
import nock from 'nock';

const metadata = { issuer: 'https://op.example.com/', jwks_uri: 'https://op.example.com/.well-known/jwks.json' };

describe('logoutTokenVerifier', () => {
  let verify: VerifyLogoutToken;
  let jwksSpy: jest.SpyInstance;

  beforeEach(() => {
    jwksSpy = jest.fn().mockReturnValue(jwks);
    verify = getLogoutTokenVerifier();
    nock('https://op.example.com').get('/.well-known/jwks.json').reply(200, jwksSpy);
  });

  afterEach(() => {
    nock.cleanAll();
    jwksSpy.mockReset();
  });

  it('should verify a valid logout token', async () => {
    const token = await makeLogoutToken({ sid: 'foo' });
    await expect(verify(token, getConfig(withApi), metadata)).resolves.toMatchObject({ sid: 'foo' });
    expect(jwksSpy).toHaveBeenCalled();
  });

  it('should cache the jwks', async () => {
    const token = await makeLogoutToken({ sid: 'foo' });
    await expect(verify(token, getConfig(withApi), metadata)).resolves.not.toThrow();
    await expect(verify(token, getConfig(withApi), metadata)).resolves.not.toThrow();
    expect(jwksSpy).toHaveBeenCalledTimes(1);
  });

  it('should verify a logout token signed with HS256', async () => {
    const token = await makeLogoutToken({ sid: 'foo' }, 'foobarbaz');
    await expect(
      verify(token, getConfig({ ...withApi, clientSecret: 'foobarbaz', idTokenSigningAlg: 'HS256' }), metadata)
    ).resolves.not.toThrow();
    expect(jwksSpy).not.toHaveBeenCalled();
  });

  it('should verify a valid logout token with just a sub', async () => {
    const token = await makeLogoutToken({ sub: 'foo' });
    await expect(verify(token, getConfig(withApi), metadata)).resolves.toMatchObject({ sub: 'foo' });
    expect(jwksSpy).toHaveBeenCalled();
  });

  it('should fail when no sid or sub', async () => {
    const token = await makeLogoutToken();
    await expect(verify(token, getConfig(withApi), metadata)).rejects.toThrow(
      'either "sid" or "sub" (or both) claims must be present'
    );
    expect(jwksSpy).toHaveBeenCalled();
  });

  it('should fail when nonce is in payload', async () => {
    const token = await makeLogoutToken({ nonce: 'foo', sid: 'bar' });
    await expect(verify(token, getConfig(withApi), metadata)).rejects.toThrow('"nonce" claim is prohibited');
    expect(jwksSpy).toHaveBeenCalled();
  });

  it('should fail when events not in payload', async () => {
    const token = await makeLogoutToken({ events: undefined, sid: 'foo' });
    await expect(verify(token, getConfig(withApi), metadata)).rejects.toThrow('"events" claim is missing');
    expect(jwksSpy).toHaveBeenCalled();
  });

  it('should fail when events not an object', async () => {
    const token = await makeLogoutToken({ events: true, sid: 'foo' });
    await expect(verify(token, getConfig(withApi), metadata)).rejects.toThrow('"events" claim must be an object');
    expect(jwksSpy).toHaveBeenCalled();
  });

  it('should fail when events missing backchannel-logout', async () => {
    const token = await makeLogoutToken({ events: {}, sid: 'foo' });
    await expect(verify(token, getConfig(withApi), metadata)).rejects.toThrow(
      '"http://schemas.openid.net/event/backchannel-logout" member is missing in the "events" claim'
    );
    expect(jwksSpy).toHaveBeenCalled();
  });

  it('should fail when events missing backchannel-logout', async () => {
    const token = await makeLogoutToken({
      events: {
        'http://schemas.openid.net/event/backchannel-logout': ''
      },
      sid: 'foo'
    });
    await expect(verify(token, getConfig(withApi), metadata)).rejects.toThrow(
      '"http://schemas.openid.net/event/backchannel-logout" member in the "events" claim must be an object'
    );
    expect(jwksSpy).toHaveBeenCalled();
  });
});
