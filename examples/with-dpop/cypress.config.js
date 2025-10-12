const { defineConfig } = require('cypress');

module.exports = defineConfig({
  chromeWebSecurity: false,
  viewportWidth: 1000,
  viewportHeight: 1000,
  fixturesFolder: false,
  reporter: 'spec', // Changed from 'junit' to show detailed console output
  reporterOptions: {
    mochaFile: 'test-results/cypress/junit-[hash].xml'
  },
  retries: {
    runMode: 1 // Reduced retries for faster feedback
  },
  env: {
    // Pass environment variables to Cypress
    CYPRESS_USER_EMAIL: process.env.CYPRESS_USER_EMAIL,
    CYPRESS_USER_PASSWORD: process.env.CYPRESS_USER_PASSWORD,
    USER_EMAIL: process.env.CYPRESS_USER_EMAIL,
    USER_PASSWORD: process.env.CYPRESS_USER_PASSWORD
  },
  e2e: {
    setupNodeEvents(on, config) {
      // Log test events for debugging
      on('task', {
        log(message) {
          console.log(message);
          return null;
        }
      });
      
      // Pass environment variables at runtime
      config.env.CYPRESS_USER_EMAIL = process.env.CYPRESS_USER_EMAIL;
      config.env.CYPRESS_USER_PASSWORD = process.env.CYPRESS_USER_PASSWORD;
      config.env.USER_EMAIL = process.env.CYPRESS_USER_EMAIL;
      config.env.USER_PASSWORD = process.env.CYPRESS_USER_PASSWORD;
      
      return config;
    },
    baseUrl: 'http://localhost:3000', // Updated back to 3000 - servers start cleanly now
    video: true,
    screenshotOnRunFailure: true,
    defaultCommandTimeout: 10000,
    requestTimeout: 10000,
    responseTimeout: 10000
  }
});
