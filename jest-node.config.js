const base = require('./jest-base.config');

/** @type {import('jest').Config} */
module.exports = {
  ...base,
  displayName: 'node',
  testEnvironment: 'jest-environment-node-single-context'
};
