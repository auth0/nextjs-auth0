import { getAll as getCookies, clear as clearCookie, set as setCookie } from '../utils/cookies';
import { CookieSerializeOptions } from 'cookie';
import { IncomingMessage, ServerResponse } from 'http';
import AbstractCookieStore from './abstract-cookie-store';

export default class NodeCookieStore extends AbstractCookieStore {
  protected getCookies(req: IncomingMessage) {
    return getCookies(req);
  }

  protected setCookie(res: ServerResponse, name: string, value: string, opts: CookieSerializeOptions) {
    return setCookie(res, name, value, opts);
  }

  protected clearCookie(res: ServerResponse, name: string, opts: CookieSerializeOptions) {
    return clearCookie(res, name, opts);
  }
}
