# API Call Example

This example tries to show a more advanced use case where you need to call an external API from your Next.js application. The client side will call an API Route (`/api/shows`) which will act as a proxy to the external API (`http://localhost:3001/api/my/shows`).

When the call is being proxied it will fetch the access token from the session (or exchange it for a new one if it's expired, using a refresh token) and pass this along as a bearer token to the API.

In order to run this project you'll need to configure and launch the [sample-api](../sample-api) project.

## Configuration

So in order for this to work you will need to pass a few additional settings to the library:

- If your API requires specific scopes (like `read:shows`) you'll need to add this to the configuration
- By adding the `offline_access` scope you'll receive a refresh token when signing in. This is needed in order to request new access tokens.
- An audience needs to be provided for which we'll request the access token on the user's behalf. This is the audience of the sample API.

```js
AUTH0_SCOPE: 'openid profile read:shows offline_access',
API_AUDIENCE: 'https://api/tv-shows',
```

## How does this work?

We have a simple page which can list my TV shows. It doesn't do much, it simple calls an API Route. This isn't doing anything fancy, it's simply reusing the session when calling the API Route.

```js
export default function TvShows() {
  const { user, loading } = useFetchUser();
  const { response, error, isLoading } = useApi('/api/shows');

  return (
    <Layout user={user} loading={loading}>
      <h1>TV Shows</h1>

      {isLoading && <p>Loading TV shows...</p>}

      {!isLoading && response && (
        <>
          <p>My favourite TV shows:</p>
          <pre>
            {JSON.stringify(
              response.shows.map(s => s.show.name),
              null,
              2
            )}
          </pre>
        </>
      )}
    </Layout>
  );
}
```

The actual logic lives in the API Route (`/api/shows`). The token cache can be used to retrieve a valid access token (and will throw an error if it fails). The access token can then be used to call an API. The response is returned to the client which can then render the TV shows:

```js
export default async function shows(req, res) {
  try {
    const tokenCache = auth0.tokenCache(req, res);
    const { accessToken } = await tokenCache.getAccessToken({
      scopes: ['read:shows']
    });

    const url = `${config.API_BASE_URL}/api/my/shows`;
    const response = await fetch(url, {
      headers: {
        Authorization: `Bearer ${accessToken}`
      }
    });

    const shows = await response.json();
    res.status(200).json(shows);
  } catch (error) {
    console.error(error);
    res.status(error.status || 500).json({
      code: error.code,
      error: error.message
    });
  }
}
```
