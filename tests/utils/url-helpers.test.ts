import isRelative from '../../src/utils/url-helpers';

describe('url-helpers', () => {
  describe('isRelative', () => {
    test('should not allow absolute urls', () => {
      expect(isRelative('file://foo')).toEqual(false);
      expect(isRelative('https://foo')).toEqual(false);
      expect(isRelative('http://foo')).toEqual(false);
    });

    test('should allow relative urls', () => {
      expect(isRelative('/foo')).toEqual(true);
      expect(isRelative('/foo?some=value')).toEqual(true);
    });
  });
});
