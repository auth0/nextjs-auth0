import createDebug from '../utils/debug';
import { CookieSerializeOptions } from 'cookie';
import { Config } from '../config';
import { Cookies } from '../utils/cookies';

const debug = createDebug('session');

export interface SessionPayload<Session> {
  header: {
    /**
     * Timestamp (in secs) when the session was created.
     */
    iat: number;
    /**
     * Timestamp (in secs) when the session was last touched.
     */
    uat: number;
    /**
     * Timestamp (in secs) when the session expires.
     */
    exp: number;
  };

  /**
   * The session data.
   */
  data: Session;
}

const epoch = (): number => (Date.now() / 1000) | 0; // eslint-disable-line no-bitwise
export type Header = { iat: number; uat: number; exp: number; [propName: string]: unknown };
const assert = (bool: boolean, msg: string) => {
  if (!bool) {
    throw new Error(msg);
  }
};

export abstract class AbstractSession<Req, Res, Session> {
  constructor(protected config: Config, protected Cookies: new () => Cookies) {}

  abstract getSession(req: Req): Promise<SessionPayload<Session> | undefined | null>;

  abstract setSession(
    req: Req,
    res: Res,
    session: Session,
    uat: number,
    iat: number,
    exp: number,
    cookieOptions: CookieSerializeOptions,
    isNewSession: boolean
  ): Promise<void>;

  abstract deleteSession(req: Req, res: Res, cookieOptions: CookieSerializeOptions): Promise<void>;

  public async read(req: Req): Promise<[Session?, number?]> {
    const { rollingDuration, absoluteDuration } = this.config.session;

    try {
      const existingSessionValue = await this.getSession(req);

      if (existingSessionValue) {
        const { header, data } = existingSessionValue;
        const { iat, uat, exp } = header;

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

        return [data, iat];
      }
    } catch (err) {
      debug('error handling session %O', err);
    }

    return [];
  }

  public async save(req: Req, res: Res, session: Session | null | undefined, createdAt?: number): Promise<void> {
    const {
      cookie: { transient, ...cookieConfig }
    } = this.config.session;

    if (!session) {
      await this.deleteSession(req, res, cookieConfig);
      return;
    }

    const isNewSession = typeof createdAt === 'undefined';
    const uat = epoch();
    const iat = typeof createdAt === 'number' ? createdAt : uat;
    const exp = this.calculateExp(iat, uat);

    const cookieOptions: CookieSerializeOptions = {
      ...cookieConfig
    };
    if (!transient) {
      cookieOptions.expires = new Date(exp * 1000);
    }

    await this.setSession(req, res, session, uat, iat, exp, cookieOptions, isNewSession);
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
}
