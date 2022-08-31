import pAny from '../../../src/auth0-session/utils/p-any';

const delay = (ms: number, { value }: { value: number }) =>
  new Promise((resolve) => setTimeout(() => resolve(value), ms));

describe('p-any', () => {
  it('returns the first fulfilled value', async () => {
    const spy = jest.fn();
    const fixture = [
      Promise.reject(new Error('1')),
      Promise.resolve(2),
      Promise.reject(new Error('3')).finally(spy),
      Promise.resolve(4)
    ];
    await expect(pAny(fixture)).resolves.toEqual(2);
  });

  it('returns the first fulfilled value #2', async () => {
    const fixture = [delay(100, { value: 1 }), delay(10, { value: 2 }), delay(50, { value: 3 })];
    await expect(pAny(fixture)).resolves.toEqual(2);
  });

  it('rejects with errors', async () => {
    const fixture = [Promise.reject(new Error('1')), Promise.reject(new Error('2')), Promise.reject(new Error('3'))];
    await expect(pAny(fixture)).rejects.toEqual(['1', '2', '3'].map(Error));
  });
});
