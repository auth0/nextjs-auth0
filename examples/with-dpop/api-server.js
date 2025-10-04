require('dotenv').config({ path: './.env.local' });

const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const helmet = require('helmet');
const { expressjwt: jwt } = require('express-jwt');
const jwksRsa = require('jwks-rsa');
const oauth = require('oauth4webapi');

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

// Enhanced middleware for DPoP validation
const checkDpop = async (req, res, next) => {
  // Only validate DPoP if USE_DPOP is enabled
  if (process.env.USE_DPOP !== 'true') {
    return next();
  }

  try {
    // Validate JWT access token with DPoP support
    const claims = await oauth.validateJwtAccessToken(
      authorizationServer,
      req,
      audience
    );
    
    // Attach validated claims to request for use in route handlers
    req.auth = claims;
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
