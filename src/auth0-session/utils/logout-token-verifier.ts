import {
  createRemoteJWKSet,
  FlattenedJWSInput,
  GetKeyFunction,
  JWSHeaderParameters,
  jwtVerify,
  JWTPayload
} from 'jose';
import { Config } from '../config';
import { IssuerMetadata } from '../client/abstract-client';

type GetKeyFn = GetKeyFunction<JWSHeaderParameters, FlattenedJWSInput>;

export type VerifyLogoutToken = (
  logoutToken: string,
  config: Config,
  issuerMetadata: IssuerMetadata
) => Promise<JWTPayload>;

export default function getLogoutTokenVerifier(): VerifyLogoutToken {
  let remoteJwkSet: GetKeyFn;

  return async (logoutToken: string, config: Config, issuerMetadata: IssuerMetadata) => {
    let keyInput: Uint8Array | GetKeyFn;
    if (config.idTokenSigningAlg === 'RS256') {
      if (!remoteJwkSet) {
        remoteJwkSet = createRemoteJWKSet(new URL(issuerMetadata.jwks_uri!));
      }
      keyInput = remoteJwkSet;
    } else {
      keyInput = new TextEncoder().encode(config.clientSecret as string);
    }
    const { payload } = await jwtVerify(logoutToken, keyInput as Uint8Array, {
      issuer: issuerMetadata.issuer,
      audience: config.clientID,
      algorithms: [config.idTokenSigningAlg],
      requiredClaims: ['iat']
    });

    if (!('sid' in payload) && !('sub' in payload)) {
      throw new Error('either "sid" or "sub" (or both) claims must be present');
    }

    if ('nonce' in payload) {
      throw new Error('"nonce" claim is prohibited');
    }

    if (!('events' in payload)) {
      throw new Error('"events" claim is missing');
    }

    if (typeof payload.events !== 'object' || payload.events === null) {
      throw new Error('"events" claim must be an object');
    }

    if (!('http://schemas.openid.net/event/backchannel-logout' in (payload as { events?: any }).events)) {
      throw new Error('"http://schemas.openid.net/event/backchannel-logout" member is missing in the "events" claim');
    }

    if (
      typeof (payload as { events?: any }).events['http://schemas.openid.net/event/backchannel-logout'] !== 'object'
    ) {
      throw new Error(
        '"http://schemas.openid.net/event/backchannel-logout" member in the "events" claim must be an object'
      );
    }

    return payload;
  };
}
