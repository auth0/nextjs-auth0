/**
 * @jest-environment @edge-runtime/jest-environment
 */
import MiddlewareCookies from '../../src/utils/middleware-cookies';
import { NextRequest, NextResponse } from 'next/server';

const setup = (reqInit?: RequestInit): [NextRequest, NextResponse] => {
  return [new NextRequest(new URL('http://example.com'), reqInit), NextResponse.next()];
};

describe('cookie', () => {
  it('should get all cookies', async () => {
    const [req] = setup({ headers: { cookie: 'foo=bar; bar=baz;' } });
    expect(new MiddlewareCookies().getAll(req)).toMatchObject({ foo: 'bar', bar: 'baz' });
  });

  it('should get a cookie by name', async () => {
    const [req] = setup({ headers: { cookie: 'foo=bar; bar=baz;' } });
    expect(new MiddlewareCookies().getAll(req)['foo']).toEqual('bar');
  });

  it('should set a cookie', async () => {
    const [, res] = setup();
    const setter = new MiddlewareCookies();
    setter.set('foo', 'bar');
    setter.commit(res);
    expect(res.headers.get('set-cookie')).toEqual('foo=bar');
  });

  it('should set a cookie with opts', async () => {
    const [, res] = setup();
    const setter = new MiddlewareCookies();
    setter.set('foo', 'bar', { httpOnly: true, sameSite: 'strict' });
    setter.commit(res);
    expect(res.headers.get('set-cookie')).toEqual('foo=bar; HttpOnly; SameSite=Strict');
  });

  it('should not overwrite existing set cookie', async () => {
    const [, res] = setup();
    res.headers.set('set-cookie', 'foo=bar');
    const setter = new MiddlewareCookies();
    setter.set('baz', 'qux');
    setter.commit(res);
    expect(res.headers.get('set-cookie')).toEqual(['foo=bar', 'baz=qux'].join(', '));
  });

  it('should override existing cookies that equal name', async () => {
    const [, res] = setup();
    res.headers.set('set-cookie', ['foo=bar', 'baz=qux'].join(', '));
    const setter = new MiddlewareCookies();
    setter.set('foo', 'qux');
    setter.commit(res, 'foo');
    expect(res.headers.get('set-cookie')).toEqual(['baz=qux', 'foo=qux'].join(', '));
  });

  it('should override existing cookies that match name', async () => {
    const [, res] = setup();
    res.headers.set('set-cookie', ['foo.1=bar', 'foo.2=baz'].join(', '));
    const setter = new MiddlewareCookies();
    setter.set('foo', 'qux');
    setter.commit(res, 'foo');
    expect(res.headers.get('set-cookie')).toEqual('foo=qux');
  });

  it('should clear cookies', async () => {
    const [, res] = setup();
    const setter = new MiddlewareCookies();
    setter.clear('foo');
    setter.commit(res);
    expect(res.headers.get('set-cookie')).toEqual('foo=; Max-Age=0');
  });
});
