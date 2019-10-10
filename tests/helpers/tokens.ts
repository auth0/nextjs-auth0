import { JWS, JWK } from '@panva/jose';

export default function createToken(key: JWK.Key, payload: object): string {
  const now = (): number => Math.floor(Date.now() / 1000);
  const body = {
    exp: now() + 2500,
    iat: now(),
    ...payload
  };
  return JWS.sign(body, key, {
    alg: 'RS256',
    typ: 'JWT',
    kid: key.kid
  });
}
