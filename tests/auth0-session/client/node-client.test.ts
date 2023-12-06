import nock from 'nock';
import { getConfig, ConfigParameters } from '../../../src/auth0-session';
import { jwks } from '../fixtures/cert';
import pkg from '../../../package.json';
import wellKnown from '../fixtures/well-known.json';
import version from '../../../src/version';
import { NodeClient } from '../../../src/auth0-session/client/node-client';
import { UserInfoError } from '../../../src/auth0-session/utils/errors';

const defaultConfig = {
  secret: '__test_session_secret__',
  clientID: '__test_client_id__',
  clientSecret: '__test_client_secret__',
  issuerBaseURL: 'https://op.example.com',
  baseURL: 'https://example.org',
  routes: {
    callback: '/callback'
  }
};

const getClient = async (params: ConfigParameters = {}): Promise<NodeClient> => {
  return new NodeClient(getConfig({ ...defaultConfig, ...params }), {
    name: 'nextjs-auth0',
    version
  });
};

describe('node client', function () {
  beforeEach(() => {
    if (!nock.isActive()) {
      nock.activate();
    }
    nock('https://op.example.com').get('/.well-known/openid-configuration').reply(200, wellKnown);
    nock('https://op.example.com').get('/.well-known/jwks.json').reply(200, jwks);
    nock('https://op.example.com')
      .get('/userinfo')
      .reply(200, function () {
        return this.req.headers;
      });
  });

  afterEach(() => {
    nock.restore();
    nock.cleanAll();
  });

  it('should send the correct default headers', async function () {
    const client = await getClient();
    const headers = await client.userinfo('__test_token__');
    const headerProps = Object.getOwnPropertyNames(headers);

    expect(headerProps).toContain('auth0-client');

    const decodedTelemetry = JSON.parse(Buffer.from(headers['auth0-client'] as string, 'base64').toString('ascii'));

    expect(decodedTelemetry.name).toEqual('nextjs-auth0');
    expect(decodedTelemetry.version).toEqual(pkg.version);
    expect(decodedTelemetry.env.node).toEqual(process.version);

    expect(headerProps).toContain('user-agent');
    expect(headers['user-agent']).toEqual(`nextjs-auth0/${pkg.version}`);
  });

  it('should disable telemetry', async function () {
    const client = await getClient({ enableTelemetry: false });
    const headers = await client.userinfo('__test_token__');
    const headerProps = Object.getOwnPropertyNames(headers);

    expect(headerProps).not.toContain('auth0-client');
  });

  it('should not strip new headers', async function () {
    const client = await getClient();
    const response = await client.userinfo('__test_token__');
    const headerProps = Object.getOwnPropertyNames(response);

    expect(headerProps).toContain('authorization');
  });

  it('should prefer user configuration regardless of idP discovery', async function () {
    nock('https://op2.example.com')
      .get('/.well-known/openid-configuration')
      .reply(
        200,
        Object.assign({}, wellKnown, {
          id_token_signing_alg_values_supported: ['none']
        })
      );

    const client = await getClient({
      issuerBaseURL: 'https://op2.example.com',
      idTokenSigningAlg: 'RS256'
    });
    // @ts-ignore
    expect((await client.getClient()).id_token_signed_response_alg).toEqual('RS256');
  });

  it('should use discovered logout endpoint by default', async function () {
    const client = await getClient({ ...defaultConfig, idpLogout: true });
    await expect(client.endSessionUrl({})).resolves.toEqual(
      'https://op.example.com/session/end?client_id=__test_client_id__'
    );
  });

  it('should use auth0 logout endpoint if configured', async function () {
    const client = await getClient({ ...defaultConfig, idpLogout: true, auth0Logout: true });
    await expect(client.endSessionUrl({})).resolves.toEqual(
      'https://op.example.com/v2/logout?client_id=__test_client_id__'
    );
  });

  it('should use auth0 logout endpoint if domain is auth0.com', async function () {
    nock('https://foo.auth0.com')
      .get('/.well-known/openid-configuration')
      .reply(200, { ...wellKnown, issuer: 'https://foo.auth0.com/' });
    const client = await getClient({ ...defaultConfig, idpLogout: true, issuerBaseURL: 'https://foo.auth0.com' });
    await expect(client.endSessionUrl({})).resolves.toEqual(
      'https://foo.auth0.com/v2/logout?client_id=__test_client_id__'
    );
  });

  it('should use auth0 logout endpoint if domain is auth0.com and configured', async function () {
    nock('https://foo.auth0.com')
      .get('/.well-known/openid-configuration')
      .reply(200, { ...wellKnown, issuer: 'https://foo.auth0.com/' });
    const client = await getClient({
      ...defaultConfig,
      issuerBaseURL: 'https://foo.auth0.com',
      idpLogout: true,
      auth0Logout: true
    });
    await expect(client.endSessionUrl({})).resolves.toEqual(
      'https://foo.auth0.com/v2/logout?client_id=__test_client_id__'
    );
  });

  it('should use discovered logout endpoint if domain is auth0.com but configured with auth0logout false', async function () {
    nock('https://foo.auth0.com')
      .get('/.well-known/openid-configuration')
      .reply(200, {
        ...wellKnown,
        issuer: 'https://foo.auth0.com/',
        end_session_endpoint: 'https://foo.auth0.com/oidc/logout'
      });
    const client = await getClient({
      ...defaultConfig,
      issuerBaseURL: 'https://foo.auth0.com',
      idpLogout: true,
      auth0Logout: false
    });
    await expect(client.endSessionUrl({})).resolves.toEqual(
      'https://foo.auth0.com/oidc/logout?client_id=__test_client_id__'
    );
  });

  it('should create client with no end_session_endpoint', async function () {
    nock('https://op2.example.com')
      .get('/.well-known/openid-configuration')
      .reply(200, {
        ...wellKnown,
        issuer: 'https://op2.example.com',
        end_session_endpoint: undefined
      });
    const client = await getClient({ ...defaultConfig, issuerBaseURL: 'https://op2.example.com' });
    await expect(client.endSessionUrl({})).rejects.toThrowError();
  });

  it('should create custom logout for auth0', async function () {
    nock('https://test.eu.auth0.com')
      .get('/.well-known/openid-configuration')
      .reply(200, { ...wellKnown, issuer: 'https://test.eu.auth0.com/', end_session_endpoint: undefined });
    nock('https://test.eu.auth0.com').get('/.well-known/jwks.json').reply(200, jwks);

    const client = await getClient({
      issuerBaseURL: 'https://test.eu.auth0.com',
      idpLogout: true
    });
    await expect(client.endSessionUrl({ post_logout_redirect_uri: 'foo' })).resolves.toEqual(
      'https://test.eu.auth0.com/v2/logout?client_id=__test_client_id__&returnTo=foo'
    );
  });

  it('should handle limited openid-configuration', async function () {
    nock('https://op2.example.com')
      .get('/.well-known/openid-configuration')
      .reply(
        200,
        Object.assign({}, wellKnown, {
          id_token_signing_alg_values_supported: undefined,
          response_types_supported: undefined,
          response_modes_supported: 'foo',
          end_session_endpoint: undefined
        })
      );

    await expect(
      (
        await getClient({
          issuerBaseURL: 'https://op2.example.com',
          idpLogout: true
        })
      )
        // @ts-ignore
        .getClient()
    ).resolves.not.toThrow();
  });

  it('should throw DiscoveryError when discovery fails', async () => {
    nock.cleanAll();
    nock('https://op.example.com').get('/.well-known/oauth-authorization-server').reply(500);
    nock('https://op.example.com').get('/.well-known/openid-configuration').reply(500);
    await expect((await getClient()).userinfo('token')).rejects.toThrow(
      'Discovery requests failing for https://op.example.com, expected 200 OK, got: 500 Internal Server Error'
    );
  });

  it('should throw UserInfoError when userinfo fails', async () => {
    nock.cleanAll();
    nock('https://op.example.com').get('/.well-known/openid-configuration').reply(200, wellKnown);
    nock('https://op.example.com').get('/userinfo').reply(500, {});
    await expect((await getClient()).userinfo('token')).rejects.toThrow(UserInfoError);
  });

  it('should throw an error if "pushedAuthorizationRequests" is enabled and issuer does not support pushed_authorization_request_endpoint', async function () {
    nock.cleanAll();
    nock('https://op.example.com')
      .get('/.well-known/openid-configuration')
      .reply(200, {
        ...wellKnown,
        pushed_authorization_request_endpoint: undefined
      });
    const client = await getClient({ ...defaultConfig, pushedAuthorizationRequests: true });
    // @ts-ignore
    await expect(client.getClient()).rejects.toThrow(
      'pushed_authorization_request_endpoint must be configured on the issuer to use pushedAuthorizationRequests'
    );
  });

  it('should succeed if "pushedAuthorizationRequests" is enabled and issuer supports pushed_authorization_request_endpoint', async function () {
    const client = await getClient({ ...defaultConfig, pushedAuthorizationRequests: true });
    // @ts-ignore
    await expect(client.getClient()).resolves.not.toThrow()
  });
});
