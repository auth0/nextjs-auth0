import isSafeRedirect from '../../src/utils/url-helpers';

describe('url-fixtures', () => {
  describe('isSafeRedirect', () => {
    test('should not allow absolute urls', () => {
      expect(isSafeRedirect('file://foo')).toEqual(false);
      expect(isSafeRedirect('https://foo')).toEqual(false);
      expect(isSafeRedirect('http://foo')).toEqual(false);
    });

    test('should allow relative urls', () => {
      expect(isSafeRedirect('/foo')).toEqual(true);
      expect(isSafeRedirect('/foo?some=value')).toEqual(true);
    });

    test('should prevent open redirects', () => {
      expect(isSafeRedirect('//google.com')).toEqual(false);
      expect(isSafeRedirect('///google.com')).toEqual(false);
    });
  });
});
