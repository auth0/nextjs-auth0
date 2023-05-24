/**
 * @jest-environment @edge-runtime/jest-environment
 */
import Auth0NextResponse from '../../src/http/auth0-next-response';
import { NextRequest, NextResponse } from 'next/server';

const setup = (reqInit?: RequestInit): [NextRequest, NextResponse] => {
  return [new NextRequest(new URL('http://example.com'), reqInit), NextResponse.next()];
};

describe('cookie', () => {
  it('should set a cookie', async () => {
    const [, res] = setup();
    const auth0Res = new Auth0NextResponse(res);
    auth0Res.setCookie('foo', 'bar');

    expect(auth0Res.res.headers.get('set-cookie')).toEqual('foo=bar; Path=/');
  });

  it('should set a cookie with opts', async () => {
    const [, res] = setup();
    const auth0Res = new Auth0NextResponse(res);
    auth0Res.setCookie('foo', 'bar', { httpOnly: true, sameSite: 'strict' });

    expect(auth0Res.res.headers.get('set-cookie')).toEqual('foo=bar; Path=/; HttpOnly; SameSite=strict');
  });

  it('should not overwrite existing set cookie', async () => {
    const [, res] = setup();
    res.cookies.set('foo', 'bar');
    const auth0Res = new Auth0NextResponse(res);
    auth0Res.setCookie('baz', 'qux');

    expect(auth0Res.res.headers.get('set-cookie')).toEqual(['foo=bar; Path=/', 'baz=qux; Path=/'].join(', '));
  });

  it('should clear cookies', async () => {
    const [, res] = setup();
    const auth0Res = new Auth0NextResponse(res);
    auth0Res.clearCookie('foo');

    expect(auth0Res.res.headers.get('set-cookie')).toMatch(/foo=;.*Expires=.*1970/);
  });
});
