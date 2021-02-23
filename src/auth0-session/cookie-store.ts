import { IncomingMessage, ServerResponse } from 'http';
import { strict as assert, AssertionError } from 'assert';
import { JWE, JWK, JWKS, errors } from 'jose';
import { encryption as deriveKey } from './utils/hkdf';
import createDebug from './utils/debug';
import { getAll as getCookies, clear as clearCookie, set as setCookie } from './utils/cookies';
import { Config } from './config';
import { CookieSerializeOptions, serialize } from 'cookie';

const debug = createDebug('cookie-store');
const epoch = (): number => (Date.now() / 1000) | 0; // eslint-disable-line no-bitwise
const MAX_COOKIE_SIZE = 4096;
const alg = 'dir';
const enc = 'A256GCM';

const notNull = <T>(value: T | null): value is T => value !== null;

export default class CookieStore {
  private keystore: JWKS.KeyStore;

  private currentKey: JWK.OctKey | undefined;

  private chunkSize: number;

  constructor(public config: Config) {
    const secrets = Array.isArray(config.secret) ? config.secret : [config.secret];
    this.keystore = new JWKS.KeyStore();

    secrets.forEach((secretString: string, i: number) => {
      const key = JWK.asKey(deriveKey(secretString));
      if (i === 0) {
        this.currentKey = key as JWK.OctKey;
      }
      this.keystore.add(key);
    });

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

  private encrypt(payload: string, headers: { [key: string]: any }): string {
    return JWE.encrypt(payload, this.currentKey as JWK.OctKey, {
      alg,
      enc,
      ...headers
    });
  }

  private decrypt(jwe: string): JWE.completeDecrypt {
    return JWE.decrypt(jwe, this.keystore, {
      complete: true,
      contentEncryptionAlgorithms: [enc],
      keyManagementAlgorithms: [alg]
    });
  }

  private calculateExp(iat: number, uat: number): number {
    const { absoluteDuration } = this.config.session;
    const { rolling, rollingDuration } = this.config.session;

    if (typeof absoluteDuration !== 'number') {
      return uat + rollingDuration;
    }
    if (!rolling) {
      return iat + absoluteDuration;
    }
    return Math.min(uat + rollingDuration, iat + absoluteDuration);
  }

  public read(req: IncomingMessage): [{ [key: string]: any }?, number?] {
    const cookies = getCookies(req);
    const { name: sessionName, rollingDuration, absoluteDuration } = this.config.session;

    let iat;
    let uat;
    let exp;
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
        const { protected: header, cleartext } = this.decrypt(existingSessionValue);
        ({ iat, uat, exp } = header as { iat: number; uat: number; exp: number });

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

        return [JSON.parse(cleartext.toString()), iat];
      }
    } catch (err) {
      /* istanbul ignore else */
      if (err instanceof AssertionError) {
        debug('existing session was rejected because', err.message);
      } else if (err instanceof errors.JOSEError) {
        debug('existing session was rejected because it could not be decrypted', err);
      } else {
        debug('unexpected error handling session', err);
      }
    }

    return [];
  }

  public save(
    req: IncomingMessage,
    res: ServerResponse,
    session: { [key: string]: any } | undefined | null,
    createdAt?: number
  ): void {
    const {
      cookie: { transient, ...cookieConfig },
      name: sessionName
    } = this.config.session;
    const cookies = getCookies(req);

    if (!session) {
      debug('clearing all matching session cookies');
      for (const cookieName of Object.keys(cookies)) {
        if (cookieName.match(`^${sessionName}(?:\\.\\d)?$`)) {
          clearCookie(res, cookieName, {
            domain: cookieConfig.domain,
            path: cookieConfig.path
          });
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
    const value = this.encrypt(JSON.stringify(session), { iat, uat, exp });

    const chunkCount = Math.ceil(value.length / this.chunkSize);
    if (chunkCount > 1) {
      debug('cookie size greater than %d, chunking', this.chunkSize);
      for (let i = 0; i < chunkCount; i++) {
        const chunkValue = value.slice(i * this.chunkSize, (i + 1) * this.chunkSize);
        const chunkCookieName = `${sessionName}.${i}`;
        setCookie(res, chunkCookieName, chunkValue, cookieOptions);
      }
      if (sessionName in cookies) {
        clearCookie(res, sessionName, {
          domain: cookieConfig.domain,
          path: cookieConfig.path
        });
      }
    } else {
      setCookie(res, sessionName, value, cookieOptions);
      for (const cookieName of Object.keys(cookies)) {
        if (cookieName.match(`^${sessionName}\\.\\d$`)) {
          clearCookie(res, cookieName, {
            domain: cookieConfig.domain,
            path: cookieConfig.path
          });
        }
      }
    }
  }
}
