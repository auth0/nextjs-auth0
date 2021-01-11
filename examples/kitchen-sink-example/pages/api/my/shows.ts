import { promisify } from 'util';
import jwt from 'express-jwt';
import jwtAuthz from 'express-jwt-authz';
import jwksRsa from 'jwks-rsa';

const verifyJwt = promisify(
  jwt({
    secret: jwksRsa.expressJwtSecret({
      cache: true,
      rateLimit: true,
      jwksRequestsPerMinute: 5,
      jwksUri: `${process.env.AUTH0_ISSUER_BASE_URL}.well-known/jwks.json`
    }),
    audience: process.env.AUTH0_AUDIENCE,
    issuer: process.env.AUTH0_ISSUER_BASE_URL,
    algorithms: ['RS256']
  })
);

const checkScopes = promisify(jwtAuthz(['read:shows'], { failWithError: true }));

const requireScope = (apiRoute) => async (req, res) => {
  try {
    await verifyJwt(req, res);
    await checkScopes(req, res);
  } catch (e) {
    return res.status(e.statusCode).json({
      error: e.error,
      error_description: e.message
    });
  }
  return apiRoute(req, res);
};

const apiRoute = async (req, res) => {
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

export default requireScope(apiRoute);
