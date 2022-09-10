import CookieStore from '../../src/auth0-session/cookie-store';
import { generateSessionCookie } from '../../src/helpers/testing';

jest.mock('../../src/auth0-session/cookie-store');

const encryptMock = jest.spyOn(CookieStore.prototype, 'encrypt');
const weekInSeconds = 7 * 24 * 60 * 60;

describe('generate-session-cookie', () => {
  test('use the provided secret', async () => {
    await generateSessionCookie({}, { secret: '__test_secret__' });
    expect(CookieStore).toHaveBeenCalledWith(expect.objectContaining({ secret: '__test_secret__' }));
  });

  test('use the default session configuration values', async () => {
    await generateSessionCookie({}, { secret: '' });
    expect(CookieStore).toHaveBeenCalledWith(
      expect.objectContaining({
        session: { absoluteDuration: weekInSeconds, cookie: {} }
      })
    );
  });

  test('use the provided session configuration values', async () => {
    await generateSessionCookie(
      {},
      {
        secret: '',
        duration: 1000,
        domain: '__test_domain__',
        path: '__test_path__',
        transient: true,
        httpOnly: false,
        secure: false,
        sameSite: 'none'
      }
    );
    expect(CookieStore).toHaveBeenCalledWith(
      expect.objectContaining({
        session: {
          absoluteDuration: 1000,
          cookie: {
            domain: '__test_domain__',
            path: '__test_path__',
            transient: true,
            httpOnly: false,
            secure: false,
            sameSite: 'none'
          }
        }
      })
    );
  });

  test('use the provided session', async () => {
    await generateSessionCookie({ user: { foo: 'bar' } }, { secret: '' });
    expect(encryptMock).toHaveBeenCalledWith({ user: { foo: 'bar' } }, expect.anything());
  });

  test('use the current time for the header values', async () => {
    const now = Date.now();
    const current = (now / 1000) | 0;
    const clock = jest.useFakeTimers('modern');
    clock.setSystemTime(now);
    await generateSessionCookie({}, { secret: '' });
    expect(encryptMock).toHaveBeenCalledWith(expect.anything(), {
      iat: current,
      uat: current,
      exp: current + weekInSeconds
    });
    clock.restoreAllMocks();
    jest.useRealTimers();
  });

  test('return the encrypted cookie', async () => {
    encryptMock.mockResolvedValueOnce('foo');
    expect(generateSessionCookie({}, { secret: '' })).resolves.toBe('foo');
  });
});
