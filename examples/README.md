# Next.js Auth0 Examples

In this folder we'll be showing off different examples on how to use the [@auth0/nextjs-auth0](https://www.npmjs.com/package/@auth0/nextjs-auth0) package in your Next.js applications.

## Configuration

For all of the examples it will be necessary to configure your Auth0 account and your local development environment as follows.

### Configuring Auth0

Go to the [Auth0 dashboard](https://manage.auth0.com/) and create a new application of type **Web Application** and make sure to configure the following:

| Setting               | Description                                                                                                                                                            |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Allowed Callback URLs | Should be set to `http://localhost:3000/api/auth/callback` when testing locally or typically to `https://myapp.com/api/auth/callback` when deploying your application. |
| Allowed Logout URLs   | Should be set to `http://localhost:3000/` when testing locally or typically to `https://myapp.com/` when deploying your application.                                   |

### Local Development

For local development you'll just want to create a `.env.local` file with the necessary settings:

```
AUTH0_SECRET=viloxyf_z2GW6K4CT-KQD_MoLEA2wqv5jWuq4Jd0P7ymgG5GJGMpvMneXZzhK3sL (at least 32 characters, used to encrypt the cookie)
AUTH0_ISSUER_BASE_URL=https://YOUR_AUTH0_DOMAIN
AUTH0_BASE_URL=http://localhost:3000/
AUTH0_CLIENT_ID=YOUR_AUTH0_CLIENT_ID
AUTH0_CLIENT_SECRET=YOUR_AUTH0_CLIENT_SECRET
```
