import { intersect, match } from '../../src/utils/array';

describe('array', () => {
  describe('intersect', () => {
    test('should find common elements', () => {
      const requestedScopes = ['read:users', 'read:clients'];
      const providedScopes = ['read:clients', 'read:connections', 'read:users'];
      const matches = [...intersect(requestedScopes, providedScopes)];
      expect(matches).toEqual(['read:users', 'read:clients']);
    });

    test('should return empty if there are no matches', () => {
      const requestedScopes = ['read:users', 'read:clients'];
      const providedScopes = ['read:connections'];
      const matches = [...intersect(requestedScopes, providedScopes)];
      expect(matches).toEqual([]);
    });
  });

  describe('match', () => {
    test('should return true if all elements match', () => {
      const requestedScopes = ['read:users', 'read:clients'];
      const providedScopes = ['read:clients', 'read:users'];
      expect(match(requestedScopes, providedScopes)).toBeTruthy();
    });

    test('should return false if there are no matches', () => {
      const requestedScopes = ['read:users', 'read:clients'];
      const providedScopes = ['read:connections'];
      expect(match(requestedScopes, providedScopes)).toBeFalsy();
    });

    test('should return false if there are some matches', () => {
      const providedScopes = ['read:users', 'read:clients'];
      const requestedScopes = ['read:users', 'read:connections'];
      expect(match(requestedScopes, providedScopes)).toBeFalsy();
    });
  });
});
