import { IncomingMessage, ServerResponse } from 'http';
import * as jose from 'jose';
import { CookieSerializeOptions, serialize } from 'cookie';
import { encryption as deriveKey } from './utils/hkdf';
import createDebug from './utils/debug';
import { Cookies } from './utils/cookies';
import { Config } from './config';

const debug = createDebug('cookie-store');
const epoch = (): number => (Date.now() / 1000) | 0; // eslint-disable-line no-bitwise
const MAX_COOKIE_SIZE = 4096;
const alg = 'dir';
const enc = 'A256GCM';

type Header = { iat: number; uat: number; exp: number };
const notNull = <T>(value: T | null): value is T => value !== null;
const assert = (bool: boolean, msg: string) => {
  if (!bool) {
    throw new Error(msg);
  }
};

export default class CookieStore<Req = IncomingMessage, Res = ServerResponse> {
  private keys?: Uint8Array[];

  private chunkSize: number;

  constructor(private config: Config, private Cookies: new () => Cookies) {
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
      this.keys = await Promise.all(secrets.map(deriveKey));
    }
    return this.keys;
  }

  private async encrypt(payload: jose.JWTPayload, { iat, uat, exp }: Header): Promise<string> {
    const [key] = await this.getKeys();
    return await new jose.EncryptJWT({ ...payload }).setProtectedHeader({ alg, enc, uat, iat, exp }).encrypt(key);
  }

  private async decrypt(jwe: string): Promise<jose.JWTDecryptResult> {
    const keys = await this.getKeys();
    let err;
    for (let key of keys) {
      try {
        return await jose.jwtDecrypt(jwe, key);
      } catch (e) {
        err = e;
      }
    }
    throw err;
  }

  private calculateExp(iat: number, uat: number): number {
    const { absoluteDuration } = this.config.session;
    const { rolling, rollingDuration } = this.config.session;

    if (typeof absoluteDuration !== 'number') {
      return uat + (rollingDuration as number);
    }
    if (!rolling) {
      return iat + absoluteDuration;
    }
    return Math.min(uat + (rollingDuration as number), iat + absoluteDuration);
  }

  public async read(req: Req): Promise<[{ [key: string]: any }?, number?]> {
    const cookies = new this.Cookies().getAll(req);
    const { name: sessionName, rollingDuration, absoluteDuration } = this.config.session;

    let iat: number;
    let uat: number;
    let exp: number;
    let existingSessionValue;

    try {
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
        const { protectedHeader: header, payload } = await this.decrypt(existingSessionValue);
        ({ iat, uat, exp } = header as unknown as Header);

        // check that the existing session isn't expired based on options when it was established
        assert(exp > epoch(), 'it is expired based on options when it was established');

        // check that the existing session isn't expired based on current rollingDuration rules
        if (rollingDuration) {
          assert(uat + rollingDuration > epoch(), 'it is expired based on current rollingDuration rules');
        }

        // check that the existing session isn't expired based on current absoluteDuration rules
        if (typeof absoluteDuration === 'number') {
          assert(iat + absoluteDuration > epoch(), 'it is expired based on current absoluteDuration rules');
        }

        return [payload, iat];
      }
    } catch (err) {
      debug('error handling session %O', err);
    }

    return [];
  }

  public async save(
    req: Req,
    res: Res,
    session: { [key: string]: any } | undefined | null,
    createdAt?: number
  ): Promise<void> {
    const {
      cookie: { transient, ...cookieConfig },
      name: sessionName
    } = this.config.session;
    const cookieSetter = new this.Cookies();
    const cookies = cookieSetter.getAll(req);

    if (!session) {
      debug('clearing all matching session cookies');
      for (const cookieName of Object.keys(cookies)) {
        if (cookieName.match(`^${sessionName}(?:\\.\\d)?$`)) {
          cookieSetter.clear(cookieName, cookieConfig);
          cookieSetter.commit(res, this.config.session.name);
        }
      }
      return;
    }

    const uat = epoch();
    const iat = typeof createdAt === 'number' ? createdAt : uat;
    const exp = this.calculateExp(iat, uat);

    const cookieOptions: CookieSerializeOptions = {
      ...cookieConfig
    };
    if (!transient) {
      cookieOptions.expires = new Date(exp * 1000);
    }

    debug('found session, creating signed session cookie(s) with name %o(.i)', sessionName);
    const value = await this.encrypt(session, { iat, uat, exp });

    const chunkCount = Math.ceil(value.length / this.chunkSize);
    if (chunkCount > 1) {
      debug('cookie size greater than %d, chunking', this.chunkSize);
      for (let i = 0; i < chunkCount; i++) {
        const chunkValue = value.slice(i * this.chunkSize, (i + 1) * this.chunkSize);
        const chunkCookieName = `${sessionName}.${i}`;
        cookieSetter.set(chunkCookieName, chunkValue, cookieOptions);
      }
      if (sessionName in cookies) {
        cookieSetter.clear(sessionName, cookieConfig);
      }
    } else {
      cookieSetter.set(sessionName, value, cookieOptions);
      for (const cookieName of Object.keys(cookies)) {
        if (cookieName.match(`^${sessionName}\\.\\d$`)) {
          cookieSetter.clear(cookieName, cookieConfig);
        }
      }
    }
    cookieSetter.commit(res, this.config.session.name);
  }
}
