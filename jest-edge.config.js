const base = require('./jest-base.config');

/** @type {import('jest').Config} */
module.exports = {
  ...base,
  displayName: 'edge',
  testEnvironment: '@edge-runtime/jest-environment',
  testMatch: [
    '**/tests/handlers/login.test.ts',
    '**/tests/handlers/logout.test.ts',
    '**/tests/handlers/callback.test.ts',
    '**/tests/handlers/profile.test.ts',
    '**/tests/http/auth0-next-request.test.ts',
    '**/tests/http/auth0-next-response.test.ts',
    '**/tests/helpers/with-middleware-auth-required.test.ts',
    '**/tests/session/get-access-token.test.ts'
  ]
};
