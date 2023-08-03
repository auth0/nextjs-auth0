/**
 * **REMOVE-TO-TEST-ON-EDGE**@jest-environment @edge-runtime/jest-environment
 */
import Auth0NextResponse from '../../src/http/auth0-next-response';
import { NextRequest, NextResponse } from 'next/server';

const setup = (reqInit?: { headers: { cookie: string } }): [NextRequest, NextResponse] => {
  return [new NextRequest(new URL('http://example.com'), reqInit), NextResponse.next()];
};

describe('auth0-next-response', () => {
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

  it('should delete a cookie', async () => {
    const [, res] = setup();
    const auth0Res = new Auth0NextResponse(res);
    auth0Res.clearCookie('foo');

    expect(auth0Res.res.headers.get('set-cookie')).toBe('foo=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT');
  });

  it('should delete a cookie with domain option', async () => {
    const [, res] = setup();
    const auth0Res = new Auth0NextResponse(res);
    auth0Res.clearCookie('foo', { domain: 'example.com' });

    expect(auth0Res.res.headers.get('set-cookie')).toBe(
      'foo=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Domain=example.com'
    );
  });

  it('should delete a cookie with path option', async () => {
    const [, res] = setup();
    const auth0Res = new Auth0NextResponse(res);
    auth0Res.clearCookie('foo', { path: '/foo' });

    expect(auth0Res.res.headers.get('set-cookie')).toBe('foo=; Path=/foo; Expires=Thu, 01 Jan 1970 00:00:00 GMT');
  });
});
