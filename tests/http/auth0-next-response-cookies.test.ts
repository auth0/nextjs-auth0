import { cookies as nextCookies } from 'next/headers';
import { mocked } from 'ts-jest/utils';
import { Auth0NextResponseCookies } from '../../src/http';
import { NextResponse } from 'next/server';

jest.mock('next/headers');

describe('auth0-next-response', () => {
  it('should set a cookie', async () => {
    const cookies = new Auth0NextResponseCookies();
    const res = new NextResponse();
    mocked(nextCookies).mockImplementation(() => res.cookies as any);
    cookies.setCookie('foo', 'bar');
    expect(res.cookies.get('foo')?.value).toEqual('bar');
  });

  it("should warn if cookie can't be set", async () => {
    jest.spyOn(console, 'warn');
    const cookies = new Auth0NextResponseCookies();
    const res = new NextResponse();
    mocked(nextCookies).mockImplementation(
      () =>
        ({
          set() {
            throw new Error();
          }
        } as any)
    );
    cookies.setCookie('foo', 'bar');
    expect(console.warn).toHaveBeenCalledWith(
      expect.stringMatching(/cant set cookies in app dir pages or server components/)
    );
    expect(res.cookies.get('foo')).toBeUndefined();
  });

  it('should delete cookies', async () => {
    const cookies = new Auth0NextResponseCookies();
    const res = new NextResponse();
    mocked(nextCookies).mockImplementation(() => res.cookies as any);
    cookies.clearCookie('foo');
    expect(res.headers.get('set-cookie')).toEqual('foo=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT');
  });
});
