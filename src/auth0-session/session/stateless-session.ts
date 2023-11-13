import * as jose from 'jose';
import { CookieSerializeOptions, serialize } from 'cookie';
import createDebug from '../utils/debug';
import { Config } from '../config';
import { encryption } from '../utils/hkdf';
import { AbstractSession, Header, SessionPayload } from './abstract-session';
import { Auth0RequestCookies, Auth0ResponseCookies } from '../http';

const debug = createDebug('stateless-session');

const MAX_COOKIE_SIZE = 4096;
const alg = 'dir';
const enc = 'A256GCM';

const notNull = <T>(value: T | null): value is T => value !== null;

export class StatelessSession<
  Session extends { [key: string]: any } = { [key: string]: any }
> extends AbstractSession<Session> {
  private keys?: Uint8Array[];
  private chunkSize?: number;

  constructor(protected config: Config) {
    super(config);
  }

  private async getChunkSize(config: Config): Promise<number> {
    if (this.chunkSize === undefined) {
      const {
        cookie: { transient, ...cookieConfig },
        name: sessionName
      } = config.session;
      const cookieOptions: CookieSerializeOptions = {
        ...cookieConfig
      };
      if (!transient) {
        cookieOptions.expires = new Date();
      }

      const emptyCookie = serialize(`${sessionName}.0`, '', cookieOptions);
      this.chunkSize = MAX_COOKIE_SIZE - emptyCookie.length;
    }
    return this.chunkSize;
  }

  public async getKeys(config: Config): Promise<Uint8Array[]> {
    if (!this.keys) {
      const secret = config.secret;
      const secrets = Array.isArray(secret) ? secret : [secret];
      this.keys = await Promise.all(secrets.map(encryption));
    }
    return this.keys;
  }

  public async encrypt(payload: jose.JWTPayload, { iat, uat, exp }: Header, key: Uint8Array): Promise<string> {
    return await new jose.EncryptJWT({ ...payload }).setProtectedHeader({ alg, enc, uat, iat, exp }).encrypt(key);
  }

  private async decrypt(jwe: string, keys: Uint8Array[]): Promise<jose.JWTDecryptResult> {
    let err;
    for (const key of keys) {
      try {
        return await jose.jwtDecrypt(jwe, key);
      } catch (e) {
        err = e;
      }
    }
    throw err;
  }

  async getSession(req: Auth0RequestCookies): Promise<SessionPayload<Session> | undefined | null> {
    const config = await this.getConfig(req);
    const { name: sessionName } = config.session;
    const cookies = req.getCookies();
    let existingSessionValue: string | undefined;
    if (sessionName in cookies) {
      // get JWE from un-chunked session cookie
      debug('reading session from %s cookie', sessionName);
      existingSessionValue = cookies[sessionName];
    } else if (`${sessionName}.0` in cookies) {
      // get JWE from chunked session cookie
      // iterate all cookie names
      // match and filter for the ones that match sessionName.<number>
      // sort by chunk index
      // concat
      existingSessionValue = Object.entries(cookies)
        .map(([cookie, value]): [string, string] | null => {
          const match = cookie.match(`^${sessionName}\\.(\\d+)$`);
          if (match) {
            return [match[1], value as string];
          }
          return null;
        })
        .filter(notNull)
        .sort(([a], [b]) => {
          return parseInt(a, 10) - parseInt(b, 10);
        })
        .map(([i, chunk]) => {
          debug('reading session chunk from %s.%d cookie', sessionName, i);
          return chunk;
        })
        .join('');
    }
    if (existingSessionValue) {
      const keys = await this.getKeys(config);
      const { protectedHeader, payload } = await this.decrypt(existingSessionValue, keys);
      return { header: protectedHeader as unknown as Header, data: payload as Session };
    }
    return;
  }

  async setSession(
    req: Auth0RequestCookies,
    res: Auth0ResponseCookies,
    session: Session,
    uat: number,
    iat: number,
    exp: number,
    cookieOptions: CookieSerializeOptions
  ): Promise<void> {
    const config = await this.getConfig(req);
    const { name: sessionName } = config.session;
    const cookies = req.getCookies();

    debug('found session, creating signed session cookie(s) with name %o(.i)', sessionName);
    const [key] = await this.getKeys(config);
    const value = await this.encrypt(session, { iat, uat, exp }, key);

    const chunkSize = await this.getChunkSize(config);
    const chunkCount = Math.ceil(value.length / chunkSize);

    const existingCookies = new Set(
      Object.keys(cookies).filter((cookie) => cookie.match(`^${sessionName}(?:\\.\\d)?$`))
    );

    if (chunkCount > 1) {
      debug('cookie size greater than %d, chunking', this.chunkSize);
      for (let i = 0; i < chunkCount; i++) {
        const chunkValue = value.slice(i * chunkSize, (i + 1) * chunkSize);
        const chunkCookieName = `${sessionName}.${i}`;
        res.setCookie(chunkCookieName, chunkValue, cookieOptions);
        existingCookies.delete(chunkCookieName);
      }
    } else {
      res.setCookie(sessionName, value, cookieOptions);
      existingCookies.delete(sessionName);
    }

    // When the number of chunks changes due to the cookie size changing,
    // you need to delete any obsolete cookies.
    existingCookies.forEach((cookie) => res.clearCookie(cookie, cookieOptions));
  }

  async deleteSession(
    req: Auth0RequestCookies,
    res: Auth0ResponseCookies,
    cookieOptions: CookieSerializeOptions
  ): Promise<void> {
    const config = await this.getConfig(req);
    const { name: sessionName } = config.session;
    const cookies = req.getCookies();

    for (const cookieName of Object.keys(cookies)) {
      if (cookieName.match(`^${sessionName}(?:\\.\\d)?$`)) {
        res.clearCookie(cookieName, cookieOptions);
      }
    }
  }
}
