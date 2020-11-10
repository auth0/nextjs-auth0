import { Cookie, CookieJar } from 'tough-cookie';
import { JWK } from 'jose';
import { signing as deriveKey } from '../../../src/auth0-session/utils/hkdf';
import { generateCookieValue } from '../../../src/auth0-session/transient-store';
import { IncomingMessage, request as nodeHttpRequest } from 'http';
import { request as nodeHttpsRequest } from 'https';
import { ConfigParameters } from '../../../src/auth0-session';

const baseUrl = 'http://localhost:3000';
const baseUrlHttps = 'http://localhost:3000';
const secret = '__test_session_secret__';
const clientId = '__test_client_id__';
export const defaultConfig: ConfigParameters & { secret: string; baseURL: string } = {
  secret,
  clientID: clientId,
  baseURL: baseUrl,
  issuerBaseURL: 'https://op.example.com',
  authRequired: false
};

export const toSignedCookieJar = (cookies: { [key: string]: string }, url = baseUrl): CookieJar => {
  const cookieJar = new CookieJar();
  const jwk = JWK.asKey(deriveKey(secret));
  for (const [key, value] of Object.entries(cookies)) {
    cookieJar.setCookieSync(`${key}=${generateCookieValue(key, value, jwk)}`, url);
  }
  return cookieJar;
};

export const toCookieJar = (cookies: { [key: string]: string }, url = baseUrl): CookieJar => {
  const cookieJar = new CookieJar();
  for (const [key, value] of Object.entries(cookies)) {
    cookieJar.setCookieSync(`${key}=${value}`, url);
  }
  return cookieJar;
};

export const fromCookieJar = (cookieJar: CookieJar, url = baseUrl): { [key: string]: string } =>
  cookieJar.getCookiesSync(url).reduce((obj: { [key: string]: string }, { key, value }) => {
    obj[key] = value.split('.')[0];
    return obj;
  }, {});

export const getCookie = (findKey: string, cookieJar: CookieJar, url = baseUrl): Cookie | undefined =>
  cookieJar.getCookiesSync(url).find(({ key }) => key === findKey);

const request = (
  path: string,
  method = 'GET',
  {
    body,
    cookieJar,
    fullResponse,
    https
  }: { body?: { [key: string]: string }; cookieJar?: CookieJar; fullResponse?: boolean; https?: boolean }
): Promise<{ [key: string]: string } | string | { data: { [key: string]: string } | string; res: IncomingMessage }> =>
  new Promise((resolve, reject) => {
    const url = https ? baseUrlHttps : baseUrl;
    const req = (https ? nodeHttpsRequest : nodeHttpRequest)(
      {
        method,
        host: 'localhost',
        port: 3000,
        path,
        protocol: https ? 'https:' : 'http:',
        rejectUnauthorized: false
      },
      (res) => {
        if (res.statusCode && (res.statusCode < 200 || res.statusCode >= 400)) {
          return reject(new Error(res.statusMessage));
        }
        const buffers: Buffer[] = [];
        res.on('data', (chunk) => {
          buffers.push(chunk);
        });
        res.on('end', () => {
          const str = Buffer.concat(buffers).toString();
          const data = str ? JSON.parse(str) : str;
          if (fullResponse) {
            resolve({ res, data });
          } else {
            resolve(data);
          }
        });
        if (cookieJar) {
          (res.headers['set-cookie'] || []).forEach((cookie: string) => cookieJar.setCookieSync(cookie, url));
        }
      }
    );
    req.setHeader('content-type', 'application/json');
    if (cookieJar) {
      req.setHeader('cookie', cookieJar.getCookieStringSync(url));
    }
    req.on('error', reject);
    if (body) {
      req.write(JSON.stringify(body));
    }
    req.end();
  });

export const get = async (
  url: string,
  { cookieJar, fullResponse, https }: { cookieJar?: CookieJar; fullResponse?: boolean; https?: boolean } = {}
): Promise<any | Response> => {
  return request(url, 'GET', { cookieJar, fullResponse, https });
};

export const post = async (
  url: string,
  {
    cookieJar,
    body,
    fullResponse,
    https
  }: { body: { [key: string]: string }; cookieJar?: CookieJar; fullResponse?: boolean; https?: boolean }
): Promise<any | Response> => request(url, 'POST', { body, cookieJar, fullResponse, https });
