# Basic Example

This example shows the basic usage of the library with the following scenarios:

- Sign in
- Sign out
- Loading the user on the server side and adding it as part of SSR (`/pages/profile.js`)
- Loading the user on the client side and using fast/cached SSR pages (`/pages/index.js`)
- API Routes which can load the current user (`/pages/api/me.js`)
- Using hooks to make the user available throughout the application (`/lib//user.js`)

## Using this example

Configure your Auth0 account as [described here](https://github.com/auth0/nextjs-auth0#auth0-configuration) and then create a `.env` file based on the `.env.template`, eg:

```
AUTH0_DOMAIN=your-tenant.auth0.com
AUTH0_CLIENT_ID=your-auth0-client-id
AUTH0_CLIENT_SECRET=your-auth0-client-secret
REDIRECT_URI=http://localhost:3000/api/callback
POST_LOGOUT_REDIRECT_URI=http://localhost:3000/
SESSION_COOKIE_SECRET=aE1OUWcLTmSLn8I79hNJPzjTo5-aE1OUWcLTmSLn8I79hNJPzjTo5-aE1OUWcLTmSLn8I79hNJPzjTo5
```

After that you can run the example in development mode:

```bash
npm run dev
```
