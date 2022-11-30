const { defineConfig } = require('cypress');

export default defineConfig({
  chromeWebSecurity: false,
  viewportWidth: 1000,
  viewportHeight: 1000,
  fixturesFolder: false,
  reporter: 'junit',

  reporterOptions: {
    mochaFile: 'test-results/cypress/junit-[hash].xml'
  },

  retries: {
    runMode: 3
  },

  e2e: {
    baseUrl: 'http://localhost:3000',
    supportFile: false
  }
});
