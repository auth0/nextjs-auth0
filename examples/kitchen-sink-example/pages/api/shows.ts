import { withApiAuthRequired, getAccessToken } from '@auth0/nextjs-auth0';

export default withApiAuthRequired(async function shows(req, res) {
  try {
    const { accessToken } = await getAccessToken(req, res, {
      scopes: ['read:shows']
    });

    const baseUrlOrDomain = process.env.AUTH0_BASE_URL || process.env.NEXT_PUBLIC_AUTH0_BASE_URL;
    const baseURL = baseUrlOrDomain?.indexOf('http') === 0 ? baseUrlOrDomain : `https://${baseUrlOrDomain}`;

    // This is a contrived example, normally your external API would exist on another domain.
    const response = await fetch(baseURL + '/api/my/shows', {
      headers: {
        Authorization: `Bearer ${accessToken}`
      }
    });

    const shows = await response.json();
    res.status(response.status || 200).json(shows);
  } catch (error) {
    console.error(error);
    res.status(error.status || 500).json({
      code: error.code,
      error: error.message
    });
  }
});
