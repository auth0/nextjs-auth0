import { IncomingMessage, ServerResponse } from 'http';
import { strict as assert, AssertionError } from 'assert';
import onHeaders from 'on-headers';
import { JWE, JWK, JWKS, errors } from 'jose';
import { encryption as deriveKey } from './hkdf';
import weakRef from './weak-cache';
import createDebug from './debug';
import { getAll as getCookies, clear as clearCookie, set as setCookie } from './cookies';
import { Config } from './config';
import { ClientFactory } from './client';
import Session from './session';

const debug = createDebug('cookie-store');
const epoch = (): number => (Date.now() / 1000) | 0;
const CHUNK_BYTE_SIZE = 4000;
const alg = 'dir';
const enc = 'A256GCM';

const notNull = <T>(value: T | null): value is T => value !== null;

export default class CookieStore {
  private keystore: JWKS.KeyStore;
  private currentKey: JWK.OctKey | undefined;

  constructor(public config: Config, public getClient: ClientFactory) {
    const secrets = Array.isArray(config.secret) ? config.secret : [config.secret];
    this.keystore = new JWKS.KeyStore();

    secrets.forEach((secretString: string, i: number) => {
      const key = JWK.asKey(deriveKey(secretString));
      if (i === 0) {
        this.currentKey = key as JWK.OctKey;
      }
      this.keystore.add(key);
    });
  }

  private encrypt(payload: string, headers: object): string {
    console.log('alg', alg);
    console.log('enc', enc);
    console.log('key', this.currentKey);
    console.log('payload', payload);

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
    let { absoluteDuration, rolling, rollingDuration } = this.config.session;
    absoluteDuration = typeof absoluteDuration !== 'number' ? 0 : absoluteDuration;

    if (!rolling) {
      return iat + absoluteDuration;
    }

    return Math.min(...[uat + rollingDuration, iat + absoluteDuration].filter(Boolean));
  }

  private read(req: IncomingMessage, res: ServerResponse) {
    const cookies = getCookies(req);
    const { name: sessionName, rollingDuration, absoluteDuration } = this.config.session;

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

        this.set(req, res, Session.fromString(cleartext.toString(), this.config, this.getClient, iat));
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
  }

  private save(req: IncomingMessage, res: ServerResponse) {
    const ref = weakRef(req);
    const session = ref.session;

    const {
      cookie: { transient, ...cookieConfig },
      name: sessionName
    } = this.config.session;

    if (!session) {
      debug('clearing all matching session cookies');
      for (const cookieName of Object.keys(getCookies(req))) {
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
    const { createdAt = uat } = session;
    const iat = createdAt;
    const exp = this.calculateExp(iat, uat);

    const cookieOptions = {
      ...cookieConfig,
      maxAge: transient ? -1 : exp, // @TODO check
      secure: 'secure' in cookieConfig ? cookieConfig.secure : req.url?.startsWith('https:') // @TODO check
    };

    debug('found session, creating signed session cookie(s) with name %o(.i)', sessionName);
    const value = this.encrypt(session.toString(), { iat, uat, exp });

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

  public get(req: IncomingMessage, res: ServerResponse) {
    const ref = weakRef(req);
    if (!ref.session) {
      this.read(req, res);
    }
    return ref.session;
  }

  public set(req: IncomingMessage, res: ServerResponse, session: Session | null) {
    const ref = weakRef(req);
    ref.session = session;
    if (!ref.sessionSaved) {
      ref.sessionSaved = true;
      onHeaders(res, () => this.save(req, res));
    }
  }

  public delete(req: IncomingMessage, res: ServerResponse) {
    this.set(req, res, null);
  }
}
