import { assertCtx, assertReqRes } from '../../src/utils/assert';

describe('assert', () => {
  describe('assertCtx', () => {
    test('should throw with missing req', () => {
      expect(assertCtx.bind(null, {} as any)).toThrow('Request is not available');
    });

    test('should throw with missing res', () => {
      expect(assertCtx.bind(null, { req: true, res: false } as any)).toThrow('Response is not available');
    });

    test('should not throw when req and res are provided', () => {
      expect(assertCtx.bind(null, { req: true, res: true } as any)).not.toThrow();
    });
  });

  describe('assertReqRes', () => {
    test('should throw with missing req', () => {
      expect(assertReqRes.bind(null)).toThrow('Request is not available');
    });

    test('should throw with missing res', () => {
      expect(assertReqRes.bind(null, true as any)).toThrow('Response is not available');
    });

    test('should not throw when req and res are provided', () => {
      expect(assertReqRes.bind(null, true as any, true as any)).not.toThrow();
    });
  });
});
