# Contribution

Please read [Auth0's contribution guidelines](https://github.com/auth0/open-source-template/blob/master/GENERAL-CONTRIBUTING.md).

## Environment setup

- Make sure you have node and npm installed
- Run `npm install` to install dependencies
- Follow the local development steps below to get started

## Local development

- `npm install`: install dependencies
- `npm run build`: Build the binary
- `npm run build:test`: Do this once to build the test harness for the tests
- `npm test`: Run the unit tests
- `npm run test:watch`: Run the unit tests and watch for changes
- `npm run install:example`: Install the examples
- Setup the examples https://github.com/auth0/nextjs-auth0/tree/main/example-app
- `npm run start:example`: Run the example
- `npm run test:example`: Run the E2E tests (you will need to populate the `CYPRESS_USER_EMAIL` and `CYPRESS_USER_PASSWORD` env vars)
- `npm run test:example:watch`: Run the E2E tests and watch for changes

## Running examples against a mock openid provider

Your env vars in `/example-app/.env.local` should look like

```bash
AUTH0_SECRET=#ANY LONG RANDOM VALUE
AUTH0_ISSUER_BASE_URL=http://localhost:3000/oidc
AUTH0_BASE_URL=http://localhost:3000
AUTH0_CLIENT_ID=testing
AUTH0_CLIENT_SECRET=testing
```

Then run one of the commands:

- `start:example-local`: Run the example app with a mock openid provider
- `test:example-local`: Run the E2E tests with a mock openid provider
- `test:example-local:watch`: Run the E2E tests with a mock openid provider and watch for changes
