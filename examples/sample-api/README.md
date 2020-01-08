# Sample API

This sample API is used as a backend by the examples. There are two endpoints available:

- `/api/shows` which doesn't require any authentication
- `/api/my/shows` which returns the shows of the current user.

## Configuration

First you'll need to go to the [Auth0 dashboard](https://manage.auth0.com/) and create a new API under the **APIs** section:

- Name: **TV Shows API**
- Identifier: **https://api/tv-shows**
- Signing Algorithm: **RS256**

Once the API is created make sure you also create a scope: `read:shows`

Then create a `.env` file in this directory:

```
AUTH0_DOMAIN=<YOUR_AUTH0_DOMAIN> (eg: sandrino-dev.auth0.com)
AUTH0_API_IDENTIFIER=https://api/tv-shows
```

## Running

To run the API simply run the following commands:

```bash
npm install
npm start
```
