import { NextJwtVerifier } from '@serverless-jwt/next';
import { NextAuthenticatedApiRequest } from '@serverless-jwt/next/dist/types';
import { NextApiHandler, NextApiRequest, NextApiResponse } from 'next';

const verifyJwt = NextJwtVerifier({
  issuer: process.env.AUTH0_ISSUER_BASE_URL,
  audience: process.env.AUTH0_AUDIENCE
});

const requireScope = (scope: string, apiRoute: NextApiHandler) =>
  verifyJwt(async (req: NextAuthenticatedApiRequest, res) => {
    const { claims } = req.identityContext;
    if (!claims || !claims.scope || (claims.scope as string).indexOf(scope) === -1) {
      return res.status(403).json({
        error: 'access_denied',
        error_description: `Token does not contain the required '${scope}' scope`
      });
    }
    return apiRoute(req, res) as void;
  });

const apiRoute = async (req: NextApiRequest, res: NextApiResponse) => {
  try {
    const response = await fetch('https://api.tvmaze.com/search/shows?q=identity');
    const shows = await response.json();

    res.status(200).json({ shows });
  } catch (error) {
    console.error(error);
    res.status(error.status || 500).json({
      code: error.code,
      error: error.message
    });
  }
};

export default requireScope('read:shows', apiRoute);
