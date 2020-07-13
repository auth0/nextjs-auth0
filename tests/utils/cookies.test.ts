import timekeeper from 'timekeeper';
import { serialize } from 'cookie';

import getRequestResponse from '../helpers/http';
import { setCookie } from '../../src/utils/cookies';

const originalEnv = process.env.NODE_ENV;
const timeString = 'Tue, 01 Jan 2019 01:17:41 GMT';

describe('cookies', () => {
  beforeEach(() => {
    const time = new Date(1546304461001);
    timekeeper.freeze(time);
  });

  afterEach(() => {
    timekeeper.reset();
    process.env.NODE_ENV = originalEnv;
  });

  describe('when running in production', () => {
    beforeEach(() => {
      process.env.NODE_ENV = 'production';
    });

    test('should set the cookie on the response', () => {
      const { req, res } = getRequestResponse();

      setCookie(req, res, {
        name: 'foo',
        value: 'bar',
        maxAge: 1000,
        path: '/'
      });

      expect(res.setHeader.mock.calls).toEqual([
        ['Set-Cookie', [`foo=bar; Max-Age=1000; Path=/; Expires=${timeString}; HttpOnly`]]
      ]);
    });

    test('should keep the previously set cookie on the response', () => {
      const { req, res } = getRequestResponse();
      const previousCookie = serialize('previous', 'value');
      res.getHeader.mockReturnValueOnce([previousCookie]);
      setCookie(req, res, {
        name: 'foo',
        value: 'bar',
        maxAge: 1000,
        path: '/'
      });

      expect(res.setHeader.mock.calls).toEqual([
        ['Set-Cookie', [`foo=bar; Max-Age=1000; Path=/; Expires=${timeString}; HttpOnly`, previousCookie]]
      ]);
    });

    test('should keep the previously set single string cookie on the response', () => {
      const { req, res } = getRequestResponse();
      const previousCookie = serialize('previous', 'value');
      res.getHeader.mockReturnValueOnce(previousCookie);
      setCookie(req, res, {
        name: 'foo',
        value: 'bar',
        maxAge: 1000,
        path: '/'
      });

      expect(res.setHeader.mock.calls).toEqual([
        ['Set-Cookie', [`foo=bar; Max-Age=1000; Path=/; Expires=${timeString}; HttpOnly`, previousCookie]]
      ]);
    });

    test('should keep multiple previously set cookies on the response', () => {
      const { req, res } = getRequestResponse();
      const previousCookies = [serialize('previous', 'value'), serialize('lady', 'gaga')];
      res.getHeader.mockReturnValueOnce(previousCookies);
      setCookie(req, res, {
        name: 'foo',
        value: 'bar',
        maxAge: 1000,
        path: '/'
      });

      expect(res.setHeader.mock.calls).toEqual([
        ['Set-Cookie', [`foo=bar; Max-Age=1000; Path=/; Expires=${timeString}; HttpOnly`, ...previousCookies]]
      ]);
    });

    describe('when running on localhost', () => {
      test('should not set a secure cookie on the response', async () => {
        const { req, res } = getRequestResponse();
        req.headers.host = 'localhost';

        setCookie(req, res, {
          name: 'foo',
          value: 'bar',
          maxAge: 1000,
          path: '/'
        });

        expect(res.setHeader.mock.calls).toEqual([
          ['Set-Cookie', [`foo=bar; Max-Age=1000; Path=/; Expires=${timeString}; HttpOnly`]]
        ]);
      });
    });

    describe('when running on localhost with port', () => {
      test('should not set a secure cookie on the response', async () => {
        const { req, res } = getRequestResponse();
        req.headers.host = 'localhost:3000';

        setCookie(req, res, {
          name: 'foo',
          value: 'bar',
          maxAge: 1000,
          path: '/'
        });

        expect(res.setHeader.mock.calls).toEqual([
          ['Set-Cookie', [`foo=bar; Max-Age=1000; Path=/; Expires=${timeString}; HttpOnly`]]
        ]);
      });

      describe('when not running on localhost', () => {
        test('should set a secure cookie on the response', async () => {
          const { req, res } = getRequestResponse();
          req.headers.host = 'www.acme.com';

          setCookie(req, res, {
            name: 'foo',
            value: 'bar',
            maxAge: 1000,
            path: '/'
          });

          expect(res.setHeader.mock.calls).toEqual([
            ['Set-Cookie', [`foo=bar; Max-Age=1000; Path=/; Expires=${timeString}; HttpOnly; Secure`]]
          ]);
        });
      });
    });
  });
});
