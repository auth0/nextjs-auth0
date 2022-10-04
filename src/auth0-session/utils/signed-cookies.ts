import * as jose from 'jose';

export const getCookieValue = async (k: string, v: string, keys: Uint8Array[]): Promise<string | undefined> => {
  if (!v) {
    return undefined;
  }
  const [value, signature] = v.split('.');
  const flattenedJWS = {
    protected: jose.base64url.encode(JSON.stringify({ alg: 'HS256', b64: false, crit: ['b64'] })),
    payload: `${k}=${value}`,
    signature
  };
  for (const key of keys) {
    try {
      await jose.flattenedVerify(flattenedJWS, key, {
        algorithms: ['HS256']
      });
      return value;
    } catch (e) {}
  }
  return;
};

export const generateCookieValue = async (cookie: string, value: string, key: Uint8Array): Promise<string> => {
  const { signature } = await new jose.FlattenedSign(new TextEncoder().encode(`${cookie}=${value}`))
    .setProtectedHeader({ alg: 'HS256', b64: false, crit: ['b64'] })
    .sign(key);
  return `${value}.${signature}`;
};
