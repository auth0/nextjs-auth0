import * as jose from 'jose';
import { CookieSerializeOptions, serialize } from 'cookie';
import createDebug from '../utils/debug';
import { Config } from '../config';
import { Cookies } from '../utils/cookies';
import { encryption } from '../utils/hkdf';
import { AbstractSession, Header, SessionPayload } from './abstract-session';

const debug = createDebug('stateless-session');

const MAX_COOKIE_SIZE = 4096;
const alg = 'dir';
const enc = 'A256GCM';

const notNull = <T>(value: T | null): value is T => value !== null;

export class StatelessSession<
  Req,
  Res,
  Session extends { [key: string]: any } = { [key: string]: any }
> extends AbstractSession<Req, Res, Session> {
  private keys?: Uint8Array[];
  private chunkSize: number;

  constructor(protected config: Config, protected Cookies: new () => Cookies) {
    super(config, Cookies);
    const {
      cookie: { transient, ...cookieConfig },
      name: sessionName
    } = this.config.session;
    const cookieOptions: CookieSerializeOptions = {
      ...cookieConfig
    };
    if (!transient) {
      cookieOptions.expires = new Date();
    }

    const emptyCookie = serialize(`${sessionName}.0`, '', cookieOptions);
    this.chunkSize = MAX_COOKIE_SIZE - emptyCookie.length;
  }

  private async getKeys(): Promise<Uint8Array[]> {
    if (!this.keys) {
      const secret = this.config.secret;
      const secrets = Array.isArray(secret) ? secret : [secret];
      this.keys = await Promise.all(secrets.map(encryption));
    }
    return this.keys;
  }

  public async encrypt(payload: jose.JWTPayload, { iat, uat, exp }: Header): Promise<string> {
    const [key] = await this.getKeys();
    return await new jose.EncryptJWT({ ...payload }).setProtectedHeader({ alg, enc, uat, iat, exp }).encrypt(key);
  }

  private async decrypt(jwe: string): Promise<jose.JWTDecryptResult> {
    const keys = await this.getKeys();
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

  async getSession(req: Req): Promise<SessionPayload<Session> | undefined | null> {
    const { name: sessionName } = this.config.session;
    const cookies = new this.Cookies().getAll(req);
    let existingSessionValue: string | undefined;
    if (sessionName in cookies) {
      // get JWE from unchunked session cookie
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
      const { protectedHeader, payload } = await this.decrypt(existingSessionValue);
      return { header: protectedHeader as unknown as Header, data: payload as Session };
    }
    return;
  }

  async setSession(
    req: Req,
    res: Res,
    session: Session,
    uat: number,
    iat: number,
    exp: number,
    cookieOptions: CookieSerializeOptions
  ): Promise<void> {
    const { name: sessionName } = this.config.session;
    const cookieSetter = new this.Cookies();
    const cookies = cookieSetter.getAll(req);

    debug('found session, creating signed session cookie(s) with name %o(.i)', sessionName);
    const value = await this.encrypt(session, { iat, uat, exp });

    const chunkCount = Math.ceil(value.length / this.chunkSize);

    const existingCookies = new Set(
      Object.keys(cookies).filter((cookie) => cookie.match(`^${sessionName}(?:\\.\\d)?$`))
    );

    if (chunkCount > 1) {
      debug('cookie size greater than %d, chunking', this.chunkSize);
      for (let i = 0; i < chunkCount; i++) {
        const chunkValue = value.slice(i * this.chunkSize, (i + 1) * this.chunkSize);
        const chunkCookieName = `${sessionName}.${i}`;
        cookieSetter.set(chunkCookieName, chunkValue, cookieOptions);
        existingCookies.delete(chunkCookieName);
      }
    } else {
      cookieSetter.set(sessionName, value, cookieOptions);
      existingCookies.delete(sessionName);
    }

    // When the number of chunks changes due to the cookie size changing,
    // you need to delete any obsolete cookies.
    existingCookies.forEach((cookie) => cookieSetter.clear(cookie, cookieOptions));
    cookieSetter.commit(res, this.config.session.name);
  }

  async deleteSession(req: Req, res: Res, cookieOptions: CookieSerializeOptions): Promise<void> {
    const { name: sessionName } = this.config.session;
    const cookieSetter = new this.Cookies();
    const cookies = cookieSetter.getAll(req);

    for (const cookieName of Object.keys(cookies)) {
      if (cookieName.match(`^${sessionName}(?:\\.\\d)?$`)) {
        cookieSetter.clear(cookieName, cookieOptions);
        cookieSetter.commit(res, this.config.session.name);
      }
    }
  }
}
