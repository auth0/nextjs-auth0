import toSafeRedirect from '../../src/utils/url-helpers';
import payloads from '../fixtures/open-redirect-payloads.json';

describe('url-helpers', () => {
  const safeBaseUrl = new URL('http://www.example.com');

  describe('isSafeRedirect', () => {
    test('should not allow absolute urls', () => {
      expect(toSafeRedirect('file://foo', safeBaseUrl)).toEqual(undefined);
      expect(toSafeRedirect('https://foo', safeBaseUrl)).toEqual(undefined);
      expect(toSafeRedirect('http://foo', safeBaseUrl)).toEqual(undefined);
    });

    test('should allow relative urls', () => {
      expect(toSafeRedirect('/foo', safeBaseUrl)).toEqual('http://www.example.com/foo');
      expect(toSafeRedirect('foo', safeBaseUrl)).toEqual('http://www.example.com/foo');
      expect(toSafeRedirect('/foo?some=value', safeBaseUrl)).toEqual('http://www.example.com/foo?some=value');
      expect(toSafeRedirect('/foo?someUrl=https://www.google.com', safeBaseUrl)).toEqual(
        'http://www.example.com/foo?someUrl=https://www.google.com'
      );
      expect(toSafeRedirect('/foo', new URL('http://www.example.com:8888'))).toEqual('http://www.example.com:8888/foo');
    });

    test('should prevent open redirects', () => {
      for (const payload of payloads) {
        expect(toSafeRedirect(payload, safeBaseUrl) || safeBaseUrl.toString()).toMatch(/^http:\/\/www.example.com\//);
      }
    });

    test('should not throw for empty redirect', () => {
      expect(toSafeRedirect.bind(null, '', safeBaseUrl)).not.toThrow();
    });
  });
});
