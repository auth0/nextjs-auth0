beforeEach(() => {
  jest.spyOn(console, 'warn').mockImplementation(() => {
    // noop
  });
});

afterEach(() => {
  jest.restoreAllMocks();
  jest.resetModules();
});
