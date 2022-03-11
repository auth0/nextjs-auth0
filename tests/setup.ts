beforeEach(() => {
  jest.spyOn(console, 'warn').mockImplementation(() => {
    // noop
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
