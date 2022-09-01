beforeEach(() => {
  jest.spyOn(console, 'warn').mockImplementation(() => {
    // no-op
  });
});

let mockActualReact: any;

jest.doMock('react', () => {
  if (!mockActualReact) {
    mockActualReact = jest.requireActual('react');
  }
  return mockActualReact;
});

afterEach(() => {
  jest.clearAllMocks();
  jest.restoreAllMocks();
  jest.resetModules();
});
