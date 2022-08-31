import { IncomingMessage, ServerResponse } from 'http';
import { strict as assert, AssertionError } from 'assert';
import * as jose from 'jose';
import { CookieSerializeOptions, serialize } from 'cookie';
import { encryption as deriveKey } from './utils/hkdf';
import createDebug from './utils/debug';
import Cookies from './utils/cookies';
import pAny from './utils/p-any';
import { Config } from './config';

const debug = createDebug('cookie-store');
const epoch = (): number => (Date.now() / 1000) | 0; // eslint-disable-line no-bitwise
const MAX_COOKIE_SIZE = 4096;
const alg = 'dir';
const enc = 'A256GCM';

type Header = { iat: number; uat: number; exp: number };
const notNull = <T>(value: T | null): value is T => value !== null;

export default class CookieStore {
  private keys?: Uint8Array[];

  private chunkSize: number;

  constructor(public config: Config) {
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

  private async decrypt(jwe: string): Promise<jose.CompactDecryptResult> {
    const keys = await this.getKeys();
    return pAny(keys.map((key) => jose.compactDecrypt(jwe, key))) as Promise<jose.CompactDecryptResult>;
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

  public async read(req: any): Promise<[{ [key: string]: any }?, number?]> {
    const cookies = Cookies.getAll(req);
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
        const { protectedHeader: header, plaintext } = await this.decrypt(existingSessionValue);
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

        return [JSON.parse(new TextDecoder().decode(plaintext)), iat];
      }
    } catch (err) {
      /* istanbul ignore else */
      if (err instanceof AssertionError) {
        debug('existing session was rejected because', err.message);
      } else if (Array.isArray(err) && err[0] instanceof jose.errors.JOSEError) {
        debug('existing session was rejected because it could not be decrypted', err);
      } else {
        debug('unexpected error handling session', err);
      }
    }

    return [];
  }

  public async save(
    req: IncomingMessage,
    res: ServerResponse,
    session: { [key: string]: any } | undefined | null,
    createdAt?: number
  ): Promise<void> {
    const {
      cookie: { transient, ...cookieConfig },
      name: sessionName
    } = this.config.session;
    const cookies = Cookies.getAll(req);
    const cookieSetter = new Cookies();

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
