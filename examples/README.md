# Next.js Auth0 Examples

In this folder we'll be showing off different examples on how to use the [@auth0/nextjs-auth0](https://www.npmjs.com/package/@auth0/nextjs-auth0) package in your Next.js applications.

## Configuration

For all of the examples it will be necessary to configure your Auth0 account, your local development environment and optionally your Zeit Now environment as follows.

### Configuring Auth0

Go to the [Auth0 dashboard](https://manage.auth0.com/) and create a new application of type **Web Application** and make sure to configure the following:

| Setting               | Description                                                                                                                                                  |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Allowed Callback URLs | Should be set to `http://localhost:3000/api/callback` when testing locally or typically to `https://myapp.com/api/callback` when deploying your application. |
| Allowed Logout URLs   | Should be set to `http://localhost:3000/` when testing locally or typically to `https://myapp.com/` when deploying your application.                         |

### Configuring Next.js

Set env vars in the `.env` files. Variables prefixed `NEXT_PUBLIC_` will be available in the client-side bundle, otherwise
they will only be available in the server-side bundle. With bundle, I mean the packaged and minified JavaScript.

For Vercel-based hosting, use `now.json`, [as documented on their site](https://vercel.com/docs/configuration#project/env);
this includes serverless hosting.

### Local Development

For local development you'll just want to create a `.env` file with the necessary settings:

```
AUTH0_DOMAIN=YOUR_AUTH0_DOMAIN
AUTH0_CLIENT_ID=YOUR_AUTH0_CLIENT_ID
AUTH0_CLIENT_SECRET=YOUR_AUTH0_CLIENT_SECRET
REDIRECT_URI=http://localhost:3000/api/callback
POST_LOGOUT_REDIRECT_URI=http://localhost:3000/
SESSION_COOKIE_SECRET=viloxyf_z2GW6K4CT-KQD_MoLEA2wqv5jWuq4Jd0P7ymgG5GJGMpvMneXZzhK3sL (at least 32 characters, used to encrypt the cookie)
```

### Hosting in Vercel Now

When deploying these examples to Now.sh you'll want to update the `now.json` configuration file:

```json
{
  "build": {
    "env": {
      "AUTH0_DOMAIN": "YOUR_AUTH0_DOMAIN",
      "AUTH0_CLIENT_ID": "YOUR_AUTH0_CLIENT_ID",
      "AUTH0_CLIENT_SECRET": "@auth0_client_secret",
      "REDIRECT_URI": "https://my-website.now.sh/api/callback",
      "POST_LOGOUT_REDIRECT_URI": "https://my-website.now.sh/",
      "SESSION_COOKIE_SECRET": "@session_cookie_secret",
      "SESSION_COOKIE_LIFETIME": 7200
    }
  }
}
```

Some of these values are settings and can just be added to your repository if you want. Others are actual secrets and need to be created as such using the `now` CLI:

```bash
now secrets add auth0_client_secret YOUR_AUTH0_CLIENT_SECRET
now secrets add session_cookie_secret viloxyf_z2GW6K4CT-KQD_MoLEA2wqv5jWuq4Jd0P7ymgG5GJGMpvMneXZzhK3sL
```
