# Auth0 Next.js SDK DPoP Example

> **⚠️ IMPORTANT: Example Code Only**
> 
> This is a demonstration example for development and testing purposes. The included `api-server.js` contains intentional simplifications for clarity and is **NOT production-ready**. Before deploying to production:
> - Implement comprehensive input validation and sanitization
> - Add rate limiting to all API endpoints
> - Use structured logging instead of console.log
> - Properly handle and sanitize error messages
> - Review and address all security scanner warnings
> - Follow your organization's security best practices

This example demonstrates **DPoP (Demonstrating Proof-of-Possession)** integration with [Auth0 Next.js SDK](https://github.com/auth0/nextjs-auth0). DPoP is an OAuth 2.0 extension that enhances security by binding access tokens to the client's cryptographic key pair.

## Overview

This comprehensive example provides both **manual usage** and **automated testing** capabilities for DPoP functionality:

**🖱️ Interactive Demo:**
- Web interface for testing DPoP-bound authentication
- Real-time API calls with visual feedback
- Server-side DPoP implementation
- Comprehensive testing pattern for production validation

**🤖 Automated Testing:**
- Unit tests with Vitest for fast API validation
- E2E tests with Cypress for full browser automation
- Integration testing with live Auth0 and API servers
- Session caching to eliminate repeated manual logins

## What is DPoP?

DPoP (Demonstrating Proof-of-Possession) is a security extension for OAuth 2.0 that binds access tokens to a cryptographic key pair held by the client. This prevents token theft and misuse by requiring the client to prove possession of the private key when making requests.

**Key benefits:**
- **Enhanced Security**: Tokens are cryptographically bound to the client
- **Theft Protection**: Stolen tokens cannot be used without the private key  
- **Replay Attack Prevention**: Each request includes a unique proof-of-possession signature

## Features Demonstrated

This example shows:

- ✅ **DPoP Configuration**: Setting up ES256 key pairs for DPoP
- ✅ **Authentication Flow**: Login/logout with DPoP-bound tokens
- ✅ **Server-Side Protected API Calls**: Making DPoP-secured requests via Next.js API routes
- ✅ **Key Generation Utility**: Tool for generating DPoP key pairs
- ✅ **Error Handling**: Proper handling of DPoP nonce errors and retries
- ✅ **Automated Testing**: Comprehensive test suite for validation
- ✅ **Server-Side Implementation**: Server-side only DPoP requests with `auth0.fetchWithAuth()`

**Note**: This example demonstrates **server-side only** DPoP implementation. All DPoP-protected API calls are made through Next.js API routes using the server-side Auth0 client.

## Test Architecture

### 1. Unit Tests (Vitest)
- **Location**: `tests/api-shows.test.js`
- **Purpose**: Fast API route testing with mocked dependencies
- **Coverage**: Authentication, DPoP headers, error handling, edge cases

### 2. E2E Tests (Cypress)
- **Location**: `cypress/e2e/`
- **Purpose**: Full browser automation with Auth0 integration
- **Features**: Session caching, UI interaction, response validation

### 3. Integration Tests
- **Purpose**: End-to-end validation with live servers
- **Implementation**: `start-server-and-test` automation

## Quick Start

### Manual Testing

1. **Setup:**
   ```bash
   cd nextjs-auth0/examples/with-dpop
   npm install
   ```

2. **Configure environment** (see Configuration section below)

3. **Run the application:**
   ```bash
   npm run dev
   ```

4. **Test DPoP functionality:**
   - Navigate to http://localhost:3000
   - Login with Auth0
   - Click "Test Server-Side DPoP API"
   - View DPoP validation results (API calls are made server-side via Next.js API routes)

### Automated Testing

1. **Configure test user:**
   ```bash
   export CYPRESS_USER_EMAIL=test@example.com
   export CYPRESS_USER_PASSWORD=testpass123
   ```

2. **Run all tests:**
   ```bash
   npm test                    # All tests
   npm run test:unit           # Unit tests only
   npm run test:e2e            # E2E tests only
   npm run test:integration    # Integration tests only
   ```

## Project setup

Use `npm` to install the project dependencies:

```bash
npm install
```

## Configuration

### Create an API

For the **DPoP API demo** to work, you will need to [create an API](https://auth0.com/docs/authorization/apis) using the [management dashboard](https://manage.auth0.com/#/apis). This will give you an API Identifier that you can use in the `AUTH0_AUDIENCE` environment variable below.

### Configure credentials

Copy `.env.local.example` into a new file called `.env.local`, and replace the values with your own Auth0 application credentials:

```sh
# A long secret value used to encrypt the session cookie
AUTH0_SECRET='LONG_RANDOM_VALUE'
# The base url of your application
APP_BASE_URL='http://localhost:3000'
# Your Auth0 tenant domain
AUTH0_DOMAIN='YOUR_AUTH0_DOMAIN.auth0.com'
# Your Auth0 application's Client ID
AUTH0_CLIENT_ID='YOUR_AUTH0_CLIENT_ID'
# Your Auth0 application's Client Secret
AUTH0_CLIENT_SECRET='YOUR_AUTH0_CLIENT_SECRET'
# Your Auth0 API's Identifier 
# OMIT if you do not want to use the API part of the sample
AUTH0_AUDIENCE='YOUR_AUTH0_API_IDENTIFIER'
# The permissions your app is asking for
# OMIT if you do not want to use the API part of the sample
AUTH0_SCOPE='openid profile email read:shows'

# DPoP Configuration (optional)
# Set USE_DPOP=true to enable DPoP demonstration
USE_DPOP=false
# Optional: Provide your own DPoP key pair (PEM format)
# AUTH0_DPOP_PUBLIC_KEY='-----BEGIN PUBLIC KEY-----...'
# AUTH0_DPOP_PRIVATE_KEY='-----BEGIN PRIVATE KEY-----...'
```

**Note**: Make sure you replace `AUTH0_SECRET` with your own secret (you can generate a suitable string using `openssl rand -hex 32` on the command line).

## DPoP (Demonstration of Proof-of-Possession)

This sample includes support for DPoP, a security extension that provides cryptographic proof that the client making a request is in possession of a private key. This helps prevent token theft and replay attacks.

### Enabling DPoP

To enable DPoP in this sample:

1. Set `USE_DPOP=true` in your `.env.local` file
2. Optionally generate DPoP keys using: `npm run generate-dpop-keys`
3. If you don't provide keys, the sample will automatically generate them at startup

### DPoP Key Generation

You can generate ES256 key pairs for DPoP using the included utility:

```bash
npm run generate-dpop-keys
```

This will output:
- Key pairs in PEM format for environment variables
- Security notes and best practices
- Instructions for adding keys to your `.env.local` file

### Testing DPoP

When DPoP is enabled:

1. The Next.js application will use DPoP-bound access tokens server-side
2. The API server (`api-server.js`) will validate DPoP proofs
3. The `/api/shows` endpoint (Next.js API route) makes server-side DPoP requests and returns validation results
4. Run automated tests with: `npm test`

### Server-Side DPoP Implementation

This example demonstrates **server-side only** DPoP implementation:

- **Server-Side DPoP**: Uses `auth0.fetchWithAuth()` in Next.js API routes for DPoP-protected requests
- **Bearer Token Fallback**: When DPoP is disabled, falls back to standard Bearer token authentication
- **No Client-Side DPoP**: All DPoP operations are performed server-side for enhanced security

## Run the sample

### Development Mode

```bash
npm run dev
```

The app will be served at `http://localhost:3000`.

### Production Mode

```bash
npm run build
npm start
```

## Testing

### Available Test Commands

```bash
npm test                    # Run all tests (unit + E2E + integration)
npm run test:unit           # Fast unit tests with Vitest
npm run test:e2e            # Browser automation with Cypress
npm run test:integration    # End-to-end server testing
npm run test:debug          # Debug mode with detailed logging
```

### Test Configuration

For automated testing, configure these environment variables:

```bash
# Test user credentials
export CYPRESS_USER_EMAIL=test@example.com
export CYPRESS_USER_PASSWORD=testpass123

# Optional: Test configuration
export CYPRESS_baseUrl=http://localhost:3000
export API_PORT=3001
```

### Continuous Integration

The example includes GitHub Actions workflow for automated testing:

- **Location**: `.github/workflows/test.yml`
- **Features**: Automated unit tests, E2E tests, and integration validation
- **Triggers**: Pull requests, main branch pushes

## Deployment

You can deploy this app anywhere Next.js applications can be deployed.
Check out the [Next.js deployment documentation](https://nextjs.org/docs/deployment) for more details.

## What is Auth0?

Auth0 helps you to:

* Add authentication with [multiple authentication sources](https://docs.auth0.com/identityproviders), either social like **Google, Facebook, Microsoft Account, LinkedIn, GitHub, Twitter, Box, Salesforce, among others**, or enterprise identity systems like **Windows Azure AD, Google Apps, Active Directory, ADFS or any SAML Identity Provider**.
* Add authentication through more traditional **[username/password databases](https://docs.auth0.com/mysql-connection-tutorial)**.
* Add support for **[linking different user accounts](https://docs.auth0.com/link-accounts)** with the same user.
* Support for generating signed [Json Web Tokens](https://docs.auth0.com/jwt) to call your APIs and **flow the user identity** securely.
* Analytics of how, when and where users are logging in.
* Pull data from other sources and add it to the user profile, through [JavaScript rules](https://docs.auth0.com/rules).

## Create a Free Auth0 Account

1. Go to [Auth0](https://auth0.com/signup) and click Sign Up.
2. Use Google, GitHub or Microsoft Account to login.

## Issue Reporting

If you have found a bug or if you have a feature request, please report them at this repository issues section. Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.

## Author

[Auth0](https://auth0.com)

## License

This project is licensed under the MIT license. See the [LICENSE](./LICENSE) file for more info.
