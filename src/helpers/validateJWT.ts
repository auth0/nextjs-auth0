import { NextApiRequest } from 'next';
import jwkToBuffer from 'jwk-to-pem';
import jwt from 'jsonwebtoken';

// extract the token from authorisation header
const extractToken = (req: NextApiRequest) => {
  if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
    return req.headers.authorization.split(' ')[1];
  }
  return null;
};

type JWKFile = {
  keys: jwkToBuffer.JWK[];
};

/**
 * A simple function that validates a JWT agains the users JWKs.
 * It will return the JWT if its valid, otherwise it will return undefined
 */
const validateJWT: (req: NextApiRequest) => Promise<string | undefined> = async (req: NextApiRequest) => {
  const token = extractToken(req); // first extract the token
  if (!token) {
    return undefined;
  }

  // make a request to get the JWKs
  const jwks = (await (await fetch(`${process.env.AUTH0_ISSUER_BASE_URL as string}/.well-known/jwks.json`)).json()) as
    | JWKFile
    | undefined;

  if (!jwks || jwks.keys?.[0] == undefined) {
    return undefined;
  }

  // convert the jwks to a pem string
  const pem = jwkToBuffer(jwks.keys[0]);

  try {
    jwt.verify(token, pem, {
      algorithms: ['RS256']
    });
    return token;
  } catch (err) {
    return undefined;
  }
};

export default validateJWT;
