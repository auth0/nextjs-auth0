import { createState, decodeState } from '../../src/utils/state';

describe('state', () => {
  test('should be able to serialize a state', () => {
    const state = createState();
    expect(state).toBeTruthy();

    const decoded = decodeState(state);
    expect(decoded.nonce).toBeTruthy();
  });

  test('should be able to serialize a state with custom payload', () => {
    const state = createState({
      returnTo: '/profile'
    });
    expect(state).toBeTruthy();

    const decoded = decodeState(state);
    expect(decoded.returnTo).toEqual('/profile');
    expect(decoded.nonce).toBeTruthy();
  });
});
