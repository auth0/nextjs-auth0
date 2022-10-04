import { Cookie, CookieJar } from 'tough-cookie';
import { signing as deriveKey } from '../../../src/auth0-session/utils/hkdf';
import { generateCookieValue } from '../../../src/auth0-session/transient-store';
import { IncomingMessage, request as nodeHttpRequest } from 'http';
import { request as nodeHttpsRequest } from 'https';
import { ConfigParameters } from '../../../src/auth0-session';

const secret = '__test_session_secret__';
const clientId = '__test_client_id__';
export const defaultConfig: Omit<ConfigParameters, 'baseURL'> = {
  secret,
  clientID: clientId,
  issuerBaseURL: 'https://op.example.com',
  routes: {
    callback: '/callback'
  }
};

export const toSignedCookieJar = async (cookies: { [key: string]: string }, url: string): Promise<CookieJar> => {
  const cookieJar = new CookieJar();
  const signingKey = await deriveKey(secret);
  for (const [key, value] of Object.entries(cookies)) {
    cookieJar.setCookieSync(`${key}=${await generateCookieValue(key, value, signingKey)}`, url);
  }
  return cookieJar;
};

export const toCookieJar = (cookies: { [key: string]: string }, url: string): CookieJar => {
  const cookieJar = new CookieJar();
  for (const [key, value] of Object.entries(cookies)) {
    cookieJar.setCookieSync(`${key}=${value}`, url);
  }
  return cookieJar;
};

export const fromCookieJar = (cookieJar: CookieJar, url: string): { [key: string]: string } =>
  cookieJar.getCookiesSync(url).reduce((obj: { [key: string]: string }, { key, value }) => {
    obj[key] = value.split('.')[0];
    return obj;
  }, {});

export const getCookie = (findKey: string, cookieJar: CookieJar, url: string): Cookie | undefined =>
  cookieJar.getCookiesSync(url).find(({ key }) => key === findKey);

const request = (
  url: string,
  method = 'GET',
  { body, cookieJar, fullResponse }: { body?: { [key: string]: string }; cookieJar?: CookieJar; fullResponse?: boolean }
): Promise<{ [key: string]: string } | string | { data: { [key: string]: string } | string; res: IncomingMessage }> =>
  new Promise((resolve, reject) => {
    const { pathname, port, protocol, search = '' } = new URL(url);
    const req = (protocol === 'https:' ? nodeHttpsRequest : nodeHttpRequest)(
      {
        method,
        host: 'localhost',
        port,
        path: pathname + search,
        protocol,
        rejectUnauthorized: false
      },
      (res) => {
        if (cookieJar) {
          (res.headers['set-cookie'] || []).forEach((cookie: string) => cookieJar.setCookieSync(cookie, url));
        }
        if (res.statusCode && (res.statusCode < 200 || res.statusCode >= 400)) {
          return reject(new Error(res.statusMessage));
        }
        const buffers: Buffer[] = [];
        res.on('data', (chunk) => {
          buffers.push(chunk);
        });
        res.on('end', () => {
          const str = Buffer.concat(buffers).toString();
          let data;
          try {
            data = str ? JSON.parse(str) : str;
          } catch (e) {
            data = str;
          }
          if (fullResponse) {
            resolve({ res, data });
          } else {
            resolve(data);
          }
        });
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
  baseURL: string,
  path: string,
  { cookieJar, fullResponse }: { cookieJar?: CookieJar; fullResponse?: boolean } = {}
): Promise<any | Response> => {
  return request(`${baseURL}${path}`, 'GET', { cookieJar, fullResponse });
};

export const post = async (
  baseURL: string,
  path: string,
  {
    cookieJar,
    body,
    fullResponse
  }: { body: { [key: string]: any }; cookieJar?: CookieJar; fullResponse?: boolean; https?: boolean }
): Promise<any | Response> => request(`${baseURL}${path}`, 'POST', { body, cookieJar, fullResponse });
