import { cookies as nextCookies } from 'next/headers';
import { Auth0NextResponseCookies } from '../../src/http';
import { NextResponse } from 'next/server';

jest.mock('next/headers');

describe('auth0-next-response', () => {
  it('should set a cookie', async () => {
    const cookies = new Auth0NextResponseCookies();
    const res = new NextResponse();
    jest.mocked(nextCookies).mockImplementation(() => res.cookies as any);
    cookies.setCookie('foo', 'bar');
    expect(res.cookies.get('foo')?.value).toEqual('bar');
  });

  it('should not throw when setting a cookie fails', async () => {
    const cookies = new Auth0NextResponseCookies();
    jest.mocked(nextCookies).mockImplementation(
      () =>
        ({
          set: () => {
            throw new Error();
          }
        } as any)
    );
    expect(() => cookies.setCookie('foo', 'bar')).not.toThrow();
  });

  it('should delete cookies', async () => {
    const cookies = new Auth0NextResponseCookies();
    const res = new NextResponse();
    jest.mocked(nextCookies).mockImplementation(() => res.cookies as any);
    cookies.clearCookie('foo');
    expect(res.headers.get('set-cookie')).toEqual('foo=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT');
  });

  it('should not throw when deleting a cookie fails', async () => {
    const cookies = new Auth0NextResponseCookies();
    jest.mocked(nextCookies).mockImplementation(
      () =>
        ({
          delete: () => {
            throw new Error();
          }
        } as any)
    );
    expect(() => cookies.clearCookie('foo')).not.toThrow();
  });
});
