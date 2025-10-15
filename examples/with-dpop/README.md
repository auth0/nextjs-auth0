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

## Quick Start

For a rapid setup to test DPoP functionality:

### Automated Testing

1. **Configure test user:**
   ```bash
   export CYPRESS_USER_EMAIL=test@example.com
   export CYPRESS_USER_PASSWORD=testpass123
   ```

2. **Run automated tests:**
   ```bash
   npm test
   ```

### Manual Testing

1. **Complete the Configuration steps below** (required for proper setup)

2. **Install dependencies and start:**
   ```bash
   npm install
   npm run dev
   ```

3. **Test DPoP functionality:**
   - Navigate to http://localhost:3000
   - Login with Auth0
   - Click "Test Server-Side DPoP API"
   - View DPoP validation results (API calls are made server-side via Next.js API routes)

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

This example demonstrates DPoP with **multiple audiences**, requiring specific Auth0 setup for optimal functionality.

### Prerequisites

Before configuring this example, ensure you have:

1. **Auth0 Account**: [Create a free account](https://auth0.com/signup) if you don't have one
2. **Admin Access**: Ability to create applications, APIs, and configure policies in your Auth0 tenant

### Step 1: Create Auth0 Application

1. Go to [Auth0 Dashboard](https://manage.auth0.com) → **Applications**
2. Click **Create Application**
3. Choose **Regular Web Application** (required for server-side DPoP)
4. Configure the application:
   - **Name**: `DPoP Example App` (or your preferred name)
   - **Application Type**: Regular Web Application
   - **Allowed Callback URLs**: `http://localhost:3000/api/auth/callback`
   - **Allowed Logout URLs**: `http://localhost:3000`

### Step 2: Create Multiple APIs

This example requires **two APIs** to demonstrate multiple audience functionality:

#### API 1: DPoP Server (Primary API)
1. Go to **APIs** → **Create API**
2. Configure:
   - **Name**: `DPoP Demo API`
   - **Identifier**: `https://example.com` (must match `AUTH0_DPOP_AUDIENCE`)
   - **Signing Algorithm**: RS256
3. In **Settings** → **Advanced Settings**:
   - Enable **Skip consent for verifiable first-party clients**
4. Add custom scopes in **Scopes** tab:
   - `read:users` - Read user information
   - Add any other custom scopes your app needs

#### API 2: Bearer Server (Secondary API)  
1. Go to **APIs** → **Create API**
2. Configure:
   - **Name**: `Bearer Demo API`
   - **Identifier**: `resource-server-1` (must match `AUTH0_BEARER_AUDIENCE`)
   - **Signing Algorithm**: RS256
3. In **Settings** → **Advanced Settings**:
   - Enable **Skip consent for verifiable first-party clients**

### Step 3: Configure Multiple Resource Token (MRRT) Policy

To enable your application to request tokens for multiple audiences:

1. Go to **Applications** → Your DPoP Example App → **Settings**
2. Scroll to **Advanced Settings** → **Endpoints**
3. In **Application Properties**:
   - Enable **Multiple Resource Token Policy**
   - Add both API identifiers to the MRRT policy:
     - `https://example.com`
     - `resource-server-1`

> **Important**: MRRT policies allow a single authentication session to generate access tokens for multiple APIs. Only include **custom scopes** in MRRT policies—OIDC scopes (`openid`, `profile`, `email`, `offline_access`) are automatically included.

### Step 4: Configure Environment Variables

Copy `.env.local.example` into a new file called `.env.local`, and replace the values with your Auth0 application credentials:

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
# Your Auth0 issuer base URL (typically https://YOUR_DOMAIN.auth0.com)
AUTH0_ISSUER_BASE_URL='https://YOUR_AUTH0_DOMAIN.auth0.com'

# Primary API audience and scope (from Step 2, API 1)
AUTH0_AUDIENCE='https://example.com'
AUTH0_SCOPE='openid profile email offline_access'

# DPoP Configuration (required for this example)
USE_DPOP=true

# Multiple Audience Configuration
# DPoP server audience and scopes (API 1 from Step 2)
AUTH0_DPOP_AUDIENCE='https://example.com'
AUTH0_DPOP_SCOPE='openid profile read:users offline_access'

# Bearer server audience and scopes (API 2 from Step 2)  
AUTH0_BEARER_AUDIENCE='resource-server-1'
AUTH0_BEARER_SCOPE='openid profile email offline_access'

# Optional: Provide your own DPoP key pair (PEM format)
# If not provided, keys will be generated automatically
# AUTH0_DPOP_PUBLIC_KEY='-----BEGIN PUBLIC KEY-----...'
# AUTH0_DPOP_PRIVATE_KEY='-----BEGIN PRIVATE KEY-----...'
```

**Important Notes:**
- Replace `YOUR_AUTH0_DOMAIN`, `YOUR_AUTH0_CLIENT_ID`, and `YOUR_AUTH0_CLIENT_SECRET` with values from your Auth0 application
- Generate `AUTH0_SECRET` using: `openssl rand -hex 32`
- Ensure `AUTH0_DPOP_AUDIENCE` and `AUTH0_BEARER_AUDIENCE` match the API identifiers created in Step 2
- Set `USE_DPOP=true` to enable DPoP functionality

## DPoP (Demonstration of Proof-of-Possession)

This example demonstrates DPoP integration with the [Auth0 Next.js SDK](https://github.com/auth0/nextjs-auth0). DPoP is a security extension that provides cryptographic proof that the client making a request is in possession of a private key. This helps prevent token theft and replay attacks.

> **📚 Complete Documentation**: For comprehensive DPoP documentation, configuration options, and advanced usage patterns, see the [DPoP Examples](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#dpop-demonstrating-proof-of-possession) in the main SDK documentation.

## ⚠️ Important: Token Audience Validation with Multiple APIs

When using DPoP with **multiple audiences** in the same application (e.g., via MRRT policies), ensure each access token is sent **only** to its intended API. Sending a token to the wrong API will result in audience validation failures.

### How This Can Happen

When creating multiple fetcher instances for different APIs:

```javascript
// Fetcher for API 1
const fetcher1 = createFetcher({
  url: 'https://api1.example.com',
  accessTokenFactory: () => getAccessToken({
    audience: 'https://api1.example.com',
    // ...
  })
});

// Fetcher for API 2  
const fetcher2 = createFetcher({
  url: 'https://api2.example.com',
  accessTokenFactory: () => getAccessToken({
    audience: 'https://api2.example.com',
    // ...
  })
});
```

**Common mistake**: Accidentally using `fetcher1` to call endpoints that should use `fetcher2`, or vice versa. The API will reject the request with an audience mismatch error like:

```
OAUTH_JWT_CLAIM_COMPARISON_FAILED: unexpected JWT "aud" (audience) claim value
```

### Mitigation Strategies

**1. Scope fetcher instances appropriately**
- Create one fetcher per API/audience combination
- Use clear, descriptive variable names that indicate which API each fetcher targets
- Consider namespacing or module organization to prevent confusion

**2. Configure MRRT policies correctly**
- Ensure your MRRT policies include all audiences your application needs to access
- Set `skip_consent_for_verifiable_first_party_clients: true` on all APIs in MRRT policies
- Only include **custom scopes** in MRRT policies (OIDC scopes like `openid`, `profile`, `offline_access` are automatically included)

**3. Validate in development**
- Log the `aud` claim from decoded tokens during development to verify correct routing
- Implement error handling that clearly identifies audience mismatches
- Test each fetcher instance against its intended API endpoint before production deployment

**4. API server validation**
- Ensure your API servers validate the `aud` claim matches their expected audience identifier
- Use the same audience string in both Auth0 API configuration and server-side validation

### Example: Proper Token Routing

```javascript
// ✅ Correct: Each fetcher calls its own API
await fetcher1.fetchWithAuth('/users'); // Uses token with aud: "https://api1.example.com"
await fetcher2.fetchWithAuth('/orders'); // Uses token with aud: "https://api2.example.com"

// ❌ Incorrect: Wrong fetcher for the API
await fetcher1.fetchWithAuth('https://api2.example.com/orders'); // Will fail with aud mismatch
```

**Remember**: JWT audience validation is a critical security feature that prevents token misuse across different resource servers. These errors indicate your security controls are working correctly—the solution is to ensure proper token-to-API routing in your application code.

### Step 5: Verify Setup

After completing the configuration:

1. **Start the development servers**:
   ```bash
   npm install
   npm run dev
   ```

2. **Test the setup**:
   - Navigate to `http://localhost:3000`
   - Login with your Auth0 account
   - Click "Test Server-Side DPoP API" 
   - Click "Test Bearer API"
   - Both should return successful responses with token information

## Troubleshooting Setup

### Common Issues and Solutions

#### 1. "Audience validation failed" errors
**Problem**: API returns `OAUTH_JWT_CLAIM_COMPARISON_FAILED` or similar audience errors

**Solutions**:
- Verify API identifiers in Auth0 dashboard match environment variables exactly
- Check that `AUTH0_DPOP_AUDIENCE` matches the DPoP API identifier
- Ensure `AUTH0_BEARER_AUDIENCE` matches the Bearer API identifier

#### 2. "Grant type not allowed" errors  
**Problem**: Token exchange fails during authentication

**Solutions**:
- Ensure your Auth0 application is set to **Regular Web Application** (not SPA)
- Check that **Client Credentials** grant type is enabled in Application Settings
- Verify **Authorization Code** grant type is enabled

#### 3. MRRT policy issues
**Problem**: Cannot get tokens for multiple audiences

**Solutions**:
- Confirm MRRT policy is enabled in Application Settings → Advanced Settings
- Verify both API identifiers are added to the MRRT policy
- Ensure **Skip consent for verifiable first-party clients** is enabled on both APIs

#### 4. DPoP key generation errors
**Problem**: DPoP functionality fails to initialize

**Solutions**:
- Check that `USE_DPOP=true` in your environment variables
- Verify Node.js crypto module is available (required for key generation)
- If providing custom keys, ensure they're valid ES256 key pairs in PEM format

#### 5. Scope-related errors
**Problem**: "Insufficient scope" or scope validation failures

**Solutions**:
- Add required custom scopes to your APIs (e.g., `read:users`)
- Verify scopes in environment variables match those configured in Auth0
- Remember: OIDC scopes (`openid`, `profile`, `email`, `offline_access`) are automatically included

#### 6. Development server issues
**Problem**: API servers on ports 3001/3002 fail to start

**Solutions**:
- Check that ports 3001 and 3002 are available
- Kill any existing processes: `lsof -ti:3001,3002 | xargs kill -9`
- Restart the development server: `npm run dev`

For additional help, see the [Auth0 Next.js SDK Documentation](https://github.com/auth0/nextjs-auth0/blob/main/TROUBLESHOOTING.md).

### Quick Start

**1. Enable DPoP in your environment:**
```bash
# .env.local
USE_DPOP=true
```

**2. Generate DPoP keys (optional):**
```bash
npm run generate-dpop-keys
```

**3. Start the application:**
```bash
npm run dev
```

**4. Test DPoP functionality:**
- Navigate to http://localhost:3000
- Login and test the `/api/shows` endpoint
- View DPoP validation results

### Key Features Demonstrated

✅ **Server-Side DPoP**: Uses `auth0.createFetcher()` with DPoP enabled  
✅ **Automatic Key Generation**: Generates ES256 keys if not provided  
✅ **Nonce Error Handling**: Automatic retry on DPoP nonce errors  
✅ **Bearer Fallback**: Falls back to Bearer tokens when DPoP is disabled  
✅ **Comprehensive Testing**: Unit and E2E tests with live Auth0 integration  

### DPoP Configuration

This example supports multiple configuration methods:

**Environment Variables:**
```bash
# Enable DPoP
USE_DPOP=true

# Optional: Provide your own keys
AUTH0_DPOP_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----..."
AUTH0_DPOP_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----..."

# Optional: Configure timing
AUTH0_DPOP_CLOCK_TOLERANCE=30
AUTH0_RETRY_DELAY=100
```

**Key Generation Utility:**
```bash
npm run generate-dpop-keys
```
This outputs ES256 key pairs in PEM format ready for environment variables.

### Testing DPoP

**Manual Testing:**
1. Set `USE_DPOP=true` in `.env.local`
2. Start the application: `npm run dev`
3. Login and navigate to the protected API endpoints
4. Observe DPoP proof generation and validation

**Automated Testing:**
```bash
# Run all tests (unit + E2E)
npm test

# Run only unit tests
npm run test:unit

# Run only E2E tests
npm run test:e2e
```

### Architecture

This example demonstrates **server-side only** DPoP implementation:

- **Server-Side DPoP**: All DPoP operations happen in Next.js API routes using `auth0.createFetcher()`
- **No Client-Side DPoP**: Enhanced security by keeping private keys server-side
- **Automatic Fallback**: Gracefully falls back to Bearer authentication when DPoP is disabled
- **Real-World Patterns**: Shows production-ready error handling and retry logic

For more advanced usage patterns, production considerations, and troubleshooting, see the [SDK DPoP Documentation](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#dpop-demonstrating-proof-of-possession).

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
