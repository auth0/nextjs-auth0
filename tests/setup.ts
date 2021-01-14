beforeEach(() => {
  jest.spyOn(console, 'warn').mockImplementation(() => {
    // noop
  });
});

afterEach(() => {
  jest.clearAllMocks();
  jest.restoreAllMocks();
  jest.resetModules();
});
