const { NextJwtVerifier } = require('@serverless-jwt/next');

const verifyJwt = NextJwtVerifier({
  issuer: process.env.AUTH0_ISSUER_BASE_URL,
  audience: process.env.AUTH0_AUDIENCE
});

const requireScope = (scope, apiRoute) =>
  verifyJwt(async (req, res) => {
    const { claims } = req.identityContext;
    if (!claims || !claims.scope || claims.scope.indexOf(scope) === -1) {
      return res.status(403).json({
        error: 'access_denied',
        error_description: `Token does not contain the required '${scope}' scope`
      });
    }
    return apiRoute(req, res);
  });

  const apiRoute = async (req, res) => {
    try {
        const response = await fetch('https://api.tvmaze.com/search/shows?q=identity');
        const shows = await response.json();
    
        res.status(200).json({shows});
      } catch (error) {
        console.error(error);
        res.status(error.status || 500).json({
          code: error.code,
          error: error.message
        });
      }
  };

  export default requireScope('read:shows', apiRoute);
