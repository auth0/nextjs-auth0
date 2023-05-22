/**
 * @jest-environment @edge-runtime/jest-environment
 */
import Auth0NextRequest from '../../src/http/auth0-next-request';
import { NextRequest, NextResponse } from 'next/server';

const setup = (reqInit?: RequestInit): [NextRequest, NextResponse] => {
  return [new NextRequest(new URL('http://example.com'), reqInit), NextResponse.next()];
};

describe('cookie', () => {
  it('should get all cookies', async () => {
    const [req] = setup({ headers: { cookie: 'foo=bar; bar=baz;' } });
    expect(new Auth0NextRequest(req).getCookies()).toMatchObject({ foo: 'bar', bar: 'baz' });
  });

  it('should get all cookies in Next < 13.0.1', async () => {
    const req = {
      cookies: new Map([
        ['foo', 'bar'],
        ['bar', 'baz']
      ])
    } as unknown as NextRequest;
    expect(new Auth0NextRequest(req).getCookies()).toMatchObject({ foo: 'bar', bar: 'baz' });
  });

  it('should get a cookie by name', async () => {
    const [req] = setup({ headers: { cookie: 'foo=bar; bar=baz;' } });
    expect(new Auth0NextRequest(req).getCookies()['foo']).toEqual('bar');
  });
});
