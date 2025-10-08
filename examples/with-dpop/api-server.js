require('dotenv').config({ path: './.env.local' });

const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const helmet = require('helmet');
const { expressjwt: jwt } = require('express-jwt');
const jwksRsa = require('jwks-rsa');
const oauth = require('oauth4webapi');
const util = require('util');
const crypto = require('crypto');
const jose = require('jose');

const app = express();
const port = process.env.API_PORT || 3001;
const baseUrl = process.env.APP_BASE_URL;
const domain = process.env.AUTH0_DOMAIN;
const issuerBaseUrl = `https://${domain}`;
const audience = process.env.AUTH0_AUDIENCE;

if (!baseUrl || !domain) {
  throw new Error('Please make sure that the file .env.local is in place and populated');
}

if (!audience) {
  console.log('AUTH0_AUDIENCE not set in .env.local. Shutting down API server.');
  process.exit(1);
}

app.use(morgan('dev'));
app.use(helmet());
app.use(cors({ origin: baseUrl }));
app.use(express.json());

// Create authorization server metadata for DPoP validation
const authorizationServer = {
  issuer: issuerBaseUrl,
  jwks_uri: `${issuerBaseUrl}/.well-known/jwks.json`
};

const checkJwt = jwt({
  secret: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
    jwksUri: `${issuerBaseUrl}/.well-known/jwks.json`
  }),
  audience: audience,
  issuer: `${issuerBaseUrl}/`,
  algorithms: ['RS256']
});

// Enhanced middleware for DPoP validation using hybrid approach
const checkDpop = async (req, res, next) => {
  // Only validate DPoP if USE_DPOP is enabled
  if (process.env.USE_DPOP !== 'true') {
    return next();
  }

  try {
    // Step 1: Validate request has proper headers
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ error: 'Missing Authorization header' });
    }

    // Check if using DPoP scheme
    if (!authHeader.toLowerCase().startsWith('dpop ')) {
      return res.status(401).json({ error: 'Expected DPoP authorization scheme' });
    }

    const dpopHeader = req.headers.dpop;
    if (!dpopHeader) {
      return res.status(401).json({ error: 'Missing DPoP header' });
    }

    const accessToken = authHeader.slice(5); // Remove 'DPoP ' prefix

    // Step 2: Validate JWT access token using jose (Auth0 compatible)
    // Create JWKS fetcher
    const jwks = jose.createRemoteJWKSet(new URL(`${issuerBaseUrl}/.well-known/jwks.json`));

    // Verify JWT access token using jose
    const { payload: jwtClaims } = await jose.jwtVerify(accessToken, jwks, {
      audience: audience,
      issuer: `${issuerBaseUrl}/`,
      algorithms: ['RS256']
    });

    // Step 3: Validate DPoP proof

    // Parse DPoP proof JWT
    const dpopProofHeader = jose.decodeProtectedHeader(dpopHeader);
    const dpopProofPayload = jose.decodeJwt(dpopHeader);
    
    if (!dpopProofHeader || !dpopProofPayload) {
      return res.status(401).json({ error: 'Invalid DPoP proof format' });
    }
    
    // Check required DPoP proof headers
    if (dpopProofHeader.typ !== 'dpop+jwt') {
      return res.status(401).json({ error: 'DPoP proof must have typ: dpop+jwt' });
    }

    if (!dpopProofHeader.jwk) {
      return res.status(401).json({ error: 'DPoP proof missing jwk header' });
    }

    // Check required DPoP proof claims
    if (dpopProofPayload.htm !== req.method) {
      return res.status(401).json({ error: 'DPoP proof htm mismatch' });
    }

    const expectedHtu = `${req.protocol}://${req.get('host')}${req.originalUrl.split('?')[0]}`;
    if (dpopProofPayload.htu !== expectedHtu) {
      return res.status(401).json({ error: 'DPoP proof htu mismatch' });
    }

    // Validate access token hash (ath) claim
    const expectedAth = crypto.createHash('sha256').update(accessToken).digest('base64url');
    if (dpopProofPayload.ath !== expectedAth) {
      return res.status(401).json({ error: 'DPoP proof ath mismatch' });
    }

    // Validate timestamp - DPoP proofs should be recent (within 5 minutes)
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - dpopProofPayload.iat) > 300) {
      return res.status(401).json({ error: 'DPoP proof is not recent enough' });
    }

    // Validate DPoP proof signature using jose library
    try {
      const publicKey = await jose.importJWK(dpopProofHeader.jwk);
      
      const { payload: verifiedPayload } = await jose.jwtVerify(dpopHeader, publicKey, {
        typ: 'dpop+jwt'
      });
      
      console.log('DPoP proof signature successfully verified');
      
    } catch (err) {
      console.error('DPoP signature validation error:', err);
      return res.status(401).json({ error: 'DPoP proof signature validation failed', details: err.message });
    }

    // Attach validated claims to request for use in route handlers
    req.auth = jwtClaims;
    req.dpopProof = dpopProofPayload;
    next();
  } catch (error) {
    console.error('DPoP validation failed:', error);
    return res.status(401).json({
      error: 'DPoP validation failed',
      message: error.message
    });  
  }
};

// Apply middleware based on DPoP configuration
if (process.env.USE_DPOP === 'true') {
  app.get('/api/shows', checkDpop, (req, res) => {
    res.send({
      msg: 'Your DPoP access token was successfully validated!',
      dpopEnabled: true,
      claims: req.auth
    });
  });
} else {
  app.get('/api/shows', checkJwt, (req, res) => {
    res.send({
      msg: 'Your access token was successfully validated!',
      dpopEnabled: false
    });
  });
}

const server = app.listen(port, () => {
  console.log(`API Server listening on port ${port}`);
  console.log(`DPoP validation: ${process.env.USE_DPOP === 'true' ? 'ENABLED' : 'DISABLED'}`);
});

process.on('SIGINT', () => server.close());
