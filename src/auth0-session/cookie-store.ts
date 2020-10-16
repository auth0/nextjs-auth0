import { strict as assert, AssertionError } from 'assert';
import { JWE, JWK, JWKS, errors } from 'jose';
import { encryption as deriveKey } from './hkdf';
import weakRef from './weak-cache';
import createDebug from './debug';
import { getAll as getCookies, clear as clearCookie, set as setCookie } from './cookies';
import { IncomingMessage, ServerResponse } from 'http';
import { Config, SessionConfig } from 'auth0-session/config';

const debug = createDebug('cookie-store');
const epoch = (): number => (Date.now() / 1000) | 0;
const CHUNK_BYTE_SIZE = 4000;
const alg = 'dir';
const enc = 'A256GCM';

const notNull = <T>(value: T | null): value is T => value !== null;

export default class CookieStore {
  private config: SessionConfig;
  private keystore: JWKS.KeyStore;
  private currentKey: JWK.OctKey | undefined;

  constructor(config: Config) {
    const secrets = Array.isArray(config.secret) ? config.secret : [config.secret];
    this.config = config.session;
    this.keystore = new JWKS.KeyStore();

    secrets.forEach((secretString: string, i: number) => {
      const key = JWK.asKey(deriveKey(secretString).toString());
      if (i === 0) {
        this.currentKey = key as JWK.OctKey;
      }
      this.keystore.add(key);
    });
  }

  private encrypt(payload: string, headers: object): string {
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

  private calculateExp(iat: number, uat: number) {
    let { absoluteDuration, rolling, rollingDuration } = this.config;
    absoluteDuration = typeof absoluteDuration !== 'number' ? 0 : absoluteDuration;

    if (!rolling) {
      return iat + absoluteDuration;
    }

    return Math.min(...[uat + rollingDuration, iat + absoluteDuration].filter(Boolean));
  }

  read(req: IncomingMessage): { header: { iat?: number; uat?: number; exp?: number }; cleartext: string } {
    const ref = weakRef(req);
    if (ref.hasOwnProperty('session')) {
      return ref.session;
    }

    const cookies = getCookies(req);
    const { name: sessionName, rollingDuration, absoluteDuration } = this.config;

    let iat;
    let uat;
    let exp;
    let existingSessionValue;

    try {
      if (cookies.hasOwnProperty(sessionName)) {
        // get JWE from unchunked session cookie
        debug('reading session from %s cookie', sessionName);
        existingSessionValue = cookies[sessionName];
      } else if (cookies.hasOwnProperty(`${sessionName}.0`)) {
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

        ref.session = { header, cleartext };
      }
    } catch (err) {
      if (err instanceof AssertionError) {
        debug('existing session was rejected because', err.message);
      } else if (err instanceof errors.JOSEError) {
        debug('existing session was rejected because it could not be decrypted', err);
      } else {
        debug('unexpected error handling session', err);
      }
    }

    return ref.session;
  }

  save(req: IncomingMessage, res: ServerResponse) {
    let session = this.read(req);
    if (!session) {
      return;
    }
    const { header, cleartext } = session;
    const { uat = epoch(), iat = uat, exp = this.calculateExp(iat, uat) } = header;
    const {
      cookie: { transient, ...cookieConfig },
      name: sessionName
    } = this.config;
    const cookieOptions = {
      ...cookieConfig,
      expires: transient ? 0 : new Date(exp * 1000),
      secure: cookieConfig.hasOwnProperty('secure')
        ? cookieConfig.secure
        : req.url !== undefined && req.url.startsWith('https://') // @TODO check
    };

    debug('found session, creating signed session cookie(s) with name %o(.i)', sessionName);
    const value = this.encrypt(cleartext, {
      iat,
      uat,
      exp
    });

    const chunkCount = Math.ceil(value.length / CHUNK_BYTE_SIZE);
    if (chunkCount > 1) {
      debug('cookie size greater than %d, chunking', CHUNK_BYTE_SIZE);
      for (let i = 0; i < chunkCount; i++) {
        const chunkValue = value.slice(i * CHUNK_BYTE_SIZE, (i + 1) * CHUNK_BYTE_SIZE);
        const chunkCookieName = `${sessionName}.${i}`;
        setCookie(res, chunkCookieName, chunkValue, cookieOptions);
      }
    } else {
      setCookie(res, sessionName, value, cookieOptions);
    }
  }

  delete(req: IncomingMessage, res: ServerResponse) {
    const ref = weakRef(req);
    const { cookie: cookieOptions, name: sessionName } = this.config;
    delete ref.session;

    debug('clearing all matching session cookies');
    for (const cookieName of getCookies(req)) {
      if (cookieName.match(`^${sessionName}(?:\\.\\d)?$`)) {
        clearCookie(res, cookieName, {
          domain: cookieOptions.domain,
          path: cookieOptions.path
        });
      }
    }
  }
}
