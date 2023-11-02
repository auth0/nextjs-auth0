import createDebug from '../utils/debug';
import { CookieSerializeOptions } from 'cookie';
import { Config, GetConfig } from '../config';
import { Auth0RequestCookies, Auth0ResponseCookies } from '../http';

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

export abstract class AbstractSession<Session> {
  protected getConfig: (req: Auth0RequestCookies) => Config | Promise<Config>;

  constructor(getConfig: GetConfig) {
    this.getConfig = typeof getConfig === 'function' ? getConfig : () => getConfig;
  }

  abstract getSession(req: Auth0RequestCookies): Promise<SessionPayload<Session> | undefined | null>;

  abstract setSession(
    req: Auth0RequestCookies,
    res: Auth0ResponseCookies,
    session: Session,
    uat: number,
    iat: number,
    exp: number,
    cookieOptions: CookieSerializeOptions,
    isNewSession: boolean
  ): Promise<void>;

  abstract deleteSession(
    req: Auth0RequestCookies,
    res: Auth0ResponseCookies,
    cookieOptions: CookieSerializeOptions
  ): Promise<void>;

  public async read(req: Auth0RequestCookies): Promise<[Session?, number?]> {
    const config = await this.getConfig(req);
    const { rollingDuration, absoluteDuration } = config.session;

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

  public async save(
    req: Auth0RequestCookies,
    res: Auth0ResponseCookies,
    session: Session | null | undefined,
    createdAt?: number
  ): Promise<void> {
    const config = await this.getConfig(req);
    const {
      cookie: { transient, ...cookieConfig }
    } = config.session;

    if (!session) {
      await this.deleteSession(req, res, cookieConfig);
      return;
    }

    const isNewSession = typeof createdAt === 'undefined';
    const uat = epoch();
    const iat = typeof createdAt === 'number' ? createdAt : uat;
    const exp = this.calculateExp(iat, uat, config);

    const cookieOptions: CookieSerializeOptions = {
      ...cookieConfig
    };
    if (!transient) {
      cookieOptions.expires = new Date(exp * 1000);
    }

    await this.setSession(req, res, session, uat, iat, exp, cookieOptions, isNewSession);
  }

  private calculateExp(iat: number, uat: number, config: Config): number {
    const { absoluteDuration } = config.session;
    const { rolling, rollingDuration } = config.session;

    if (typeof absoluteDuration !== 'number') {
      return uat + (rollingDuration as number);
    }
    if (!rolling) {
      return iat + absoluteDuration;
    }
    return Math.min(uat + (rollingDuration as number), iat + absoluteDuration);
  }
}
