# Auth0 Next.js SDK DPoP Example

This example demonstrates **DPoP (Demonstrating Proof-of-Possession)** integration with [Auth0 Next.js SDK](https://github.com/auth0/nextjs-auth0). DPoP is an OAuth 2.0 extension that enhances security by binding access tokens to the client's cryptographic key pair.

## What is DPoP?

DPoP (Demonstrating Proof-of-Possession) is a security extension for OAuth 2.0 that binds access tokens to a cryptographic key pair held by the client. This prevents token theft and misuse by requiring the client to prove possession of the private key when making requests.

**Key benefits:**
- **Enhanced Security**: Tokens are cryptographically bound to the client
- **Theft Protection**: Stolen tokens cannot be used without the private key  
- **Replay Attack Prevention**: Each request includes a unique proof-of-possession signature

## Features Demonstrated

This streamlined example shows:

- ✅ **DPoP Configuration**: Setting up ES256 key pairs for DPoP
- ✅ **Authentication Flow**: Login/logout with DPoP-bound tokens
- ✅ **Protected API Calls**: Making DPoP-secured requests to external APIs
- ✅ **Key Generation Utility**: Tool for generating DPoP key pairs
- ✅ **Error Handling**: Proper handling of DPoP nonce errors and retries

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

1. The Next.js application will use DPoP-bound access tokens
2. The API server (`api-server.js`) will validate DPoP proofs
3. The `/api/shows` endpoint response will indicate if DPoP validation was successful
4. Run tests with: `npm test tests/dpop.test.js`

### DPoP vs Bearer Token Comparison

| Feature | Bearer Token | DPoP Token |
|---------|-------------|------------|
| Security | Token can be replayed if stolen | Token bound to cryptographic proof |
| Validation | Simple signature validation | Requires DPoP proof validation |
| Response | `"msg": "Your access token was successfully validated!"` | `"msg": "Your DPoP access token was successfully validated!"` |

**Note**: Make sure you replace `AUTH0_SECRET` with your own secret (you can generate a suitable string using `openssl rand -hex 32` on the command line).

## Run the sample

### Compile and hot-reload for development

This compiles and serves the Next.js app and starts the API server on port 3001.

```bash
npm run dev
```

## Deployment

### Compiles and minifies for production

```bash
npm run build
```

### Docker build

To build and run the Docker image, run `exec.sh`, or `exec.ps1` on Windows.

### Run the unit tests

```bash
npm run test
```

### Run the integration tests

```bash
npm run test:integration
```

## What is Auth0?

Auth0 helps you to:

* Add authentication with [multiple sources](https://auth0.com/docs/identityproviders), either social identity providers such as **Google, Facebook, Microsoft Account, LinkedIn, GitHub, Twitter, Box, Salesforce** (amongst others), or enterprise identity systems like **Windows Azure AD, Google Apps, Active Directory, ADFS, or any SAML Identity Provider**.
* Add authentication through more traditional **[username/password databases](https://auth0.com/docs/connections/database/custom-db)**.
* Add support for **[linking different user accounts](https://auth0.com/docs/users/user-account-linking)** with the same user.
* Support for generating signed [JSON Web Tokens](https://auth0.com/docs/tokens/json-web-tokens) to call your APIs and **flow the user identity** securely.
* Analytics of how, when, and where users are logging in.
* Pull data from other sources and add it to the user profile through [JavaScript rules](https://auth0.com/docs/rules).

## Create a Free Auth0 Account

1. Go to [Auth0](https://auth0.com) and click **Sign Up**.
2. Use Google, GitHub, or Microsoft Account to login.

## Issue Reporting

If you have found a bug or if you have a feature request, please report them at this repository issues section. Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/responsible-disclosure-policy) details the procedure for disclosing security issues.

## Author

[Auth0](https://auth0.com)

## License

This project is licensed under the MIT license. See the [LICENSE](./LICENSE) file for more info.
