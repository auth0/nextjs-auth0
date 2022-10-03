import { IncomingMessage } from 'http';
import { TLSSocket } from 'tls';
import { CookieConfig } from '../config';

// https://github.com/vercel/next.js/blob/bf8ee1edb4f6b134ada58e2ea65e33670c0c08ea/packages/next/server/next-server.ts#L2015-L2025
export const getUrl = (req: IncomingMessage): URL | void => {
  const fwdProtoHeader = req.headers['x-forwarded-proto'];
  const fwdHostHeader = req.headers['x-forwarded-host'];
  const [fwdProto] = Array.isArray(fwdProtoHeader) ? fwdProtoHeader : [fwdProtoHeader];
  const [fwdHost] = Array.isArray(fwdHostHeader) ? fwdHostHeader : [fwdHostHeader];
  const host = fwdHost || req.headers.host?.split(':')[0].toLowerCase();
  let proto = fwdProto || ((req.socket as TLSSocket).encrypted ? 'https' : 'http');
  if (req.url && proto && host) {
    return new URL(req.url, `${proto}://${host}`);
  }
};

export const enum Hints {
  Protocol,
  Host,
  CookieDomain,
  CookiePath,
  CookieSecure,
  CookieStrict
}

type HintArgs = {
  loginUrl: URL | string;
  redirectUrl: URL | string;
  domain?: string;
  path?: string;
  secure?: boolean;
  issuer: string;
};

type x = keyof HintArgs;

export class Hint {
  constructor(public type: Hints, private args: HintArgs) {}

  getMessage(): string {
    return Hint.MESSAGES[this.type].replace(
      /\{(.*?)}/g,
      (_x: string, y: keyof HintArgs) => this.args[y]?.toString() as string
    );
  }

  private static MESSAGES = {
    [Hints.Protocol]: "The Protocol of your login URL, {login}, doesn't match your redirect callback URL, {redirect}",
    [Hints.Host]: "The Host of your login URL, {login}, doesn't match your redirect callback URL, {redirect}",
    [Hints.CookieDomain]:
      'The Cookie Domain, {domain}, does not include your login URL, {login}, and callback URL, {redirect}',
    [Hints.CookiePath]:
      'The Cookie Path, {path}, does not include your login URL, {login}, and callback url, {redirect}',
    [Hints.CookieSecure]:
      "The Cookie Secure setting, {secure}, doesn't match your login URL Protocol, {login}, and your redirect callback URL Protocol, {redirect}",
    [Hints.CookieStrict]:
      'You have SameSite=Strict but your callback URL domain, {redirect}, is not the same as your authorization server domain, {issuer}'
  };
}

export const getStateMismatchHint = (
  loginReq: IncomingMessage,
  redirectUrlString: string,
  issuerBaseUrlString: string,
  cookieConfig: CookieConfig
): Hint | void => {
  const loginUrl = getUrl(loginReq);
  if (!loginUrl) {
    // Not enough information to provide a hint.
    return;
  }
  const redirectUrl = new URL(redirectUrlString);
  const { domain, path, secure, sameSite } = cookieConfig;
  const hintArgs = { loginUrl, redirectUrl, domain, path, secure, issuer: issuerBaseUrlString };

  // protocols should match
  if (loginUrl.protocol !== redirectUrl.protocol) {
    return new Hint(Hints.Protocol, hintArgs);
  }

  // host should match unless cookie domain is set then both hosts should end in domain
  if (!domain && loginUrl.hostname !== redirectUrl.hostname) {
    return new Hint(Hints.Host, hintArgs);
  }
  if (domain && !(loginUrl.hostname.endsWith(domain) || redirectUrl.hostname.endsWith(domain))) {
    return new Hint(Hints.CookieDomain, hintArgs);
  }

  // if cookie path is set, both paths should start with cookie path
  if (path && !(loginUrl.pathname.startsWith(path) && redirectUrl.pathname.startsWith(path))) {
    return new Hint(Hints.CookiePath, hintArgs);
  }

  // protocol should match cookie secure setting
  if (!!secure !== (redirectUrl.protocol === 'https:')) {
    return new Hint(Hints.CookieSecure, hintArgs);
  }

  // if cookie samesite is strict both the `issuerBaseUrl` and `redirectUrl` should be on the same 2nd and top level domain
  if (sameSite === 'strict') {
    const { hostname: issuerHostName } = new URL(issuerBaseUrlString);
    const [sld, tld] = redirectUrl.hostname.split('.').slice(-2);
    const [isld, itld] = issuerHostName.split('.').slice(-2);
    if (sld !== isld || tld !== itld) {
      return new Hint(Hints.CookieStrict, hintArgs);
    }
  }
};
