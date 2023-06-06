/** @type {import('jest').Config} */
module.exports = {
  rootDir: '.',
  moduleFileExtensions: ['ts', 'tsx', 'js'],
  preset: 'ts-jest/presets/js-with-ts',
  globalSetup: './tests/global-setup.ts',
  setupFilesAfterEnv: ['./tests/setup.ts'],
  transformIgnorePatterns: ['/node_modules/(?!oauth4webapi)']
};
