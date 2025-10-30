require('dotenv').config({ path: './.env.local' });

const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { expressjwt: jwt } = require('express-jwt');
const jwksRsa = require('jwks-rsa');
const oauth = require('oauth4webapi');

const jose = require('jose');

const baseUrl = process.env.APP_BASE_URL;
const domain = process.env.AUTH0_DOMAIN;
const issuerBaseUrl = `https://${domain}`;

if (!baseUrl || !domain) {
  throw new Error('Please make sure that the file .env.local is in place and populated');
}

// Function to find available port
async function findAvailablePort(startPort) {
  const net = require('net');
  
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    
    server.listen(startPort, (err) => {
      if (err) {
        server.close();
        findAvailablePort(startPort + 1).then(resolve).catch(reject);
      } else {
        const port = server.address().port;
        server.close(() => resolve(port));
      }
    });
    
    server.on('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        findAvailablePort(startPort + 1).then(resolve).catch(reject);
      } else {
        reject(err);
      }
    });
  });
}

// Global authorization server metadata
let authorizationServer;

async function initializeAuthorizationServer() {
  try {
    console.log(`Discovering authorization server metadata from ${issuerBaseUrl}...`);
    
    const issuer = new URL(issuerBaseUrl);
    const discoveryResponse = await oauth.discoveryRequest(issuer, {
      [oauth.allowInsecureRequests]: process.env.NODE_ENV === 'development'
    });
    
    authorizationServer = await oauth.processDiscoveryResponse(issuer, discoveryResponse);
    console.log('Authorization server metadata discovered successfully');
    
  } catch (error) {
    console.warn('Failed to discover authorization server metadata, using fallback configuration');
    authorizationServer = {
      issuer: `${issuerBaseUrl}/`,
      authorization_endpoint: `${issuerBaseUrl}/authorize`,
      token_endpoint: `${issuerBaseUrl}/oauth/token`,
      jwks_uri: `${issuerBaseUrl}/.well-known/jwks.json`,
      userinfo_endpoint: `${issuerBaseUrl}/userinfo`,
      end_session_endpoint: `${issuerBaseUrl}/oidc/logout`,
      scopes_supported: ['openid', 'profile', 'email'],
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      id_token_signing_alg_values_supported: ['RS256'],
      subject_types_supported: ['public'],
      token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic']
    };
  }
}

// Factory function to create API server for specific audience and auth method
function createApiServer(audience, serverName, forceDpop = null) {
  const app = express();

  // Rate limiting configuration
  const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100,
    message: 'Too many requests from this IP, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
  });

  // Basic middleware
  app.use(morgan('combined'));
  app.use(helmet());
  app.use(cors({ origin: baseUrl }));
  app.use(express.json());

  // JWT validation middleware for Bearer tokens
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

  // DPoP validation middleware
  const checkDpop = async (req, res, next) => {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader) {
        return res.status(401).json({ error: 'Missing Authorization header' });
      }

      if (!authHeader.toLowerCase().startsWith('dpop ')) {
        return res.status(401).json({ error: 'Expected DPoP authorization scheme' });
      }

      const dpopHeader = req.headers.dpop;
      if (!dpopHeader) {
        return res.status(401).json({ error: 'Missing DPoP header' });
      }

      const absoluteUrl = `${req.protocol}://${req.get('host')}${req.originalUrl.split('?')[0]}`;
      const request = new Request(absoluteUrl, {
        method: req.method,
        headers: {
          'authorization': authHeader,
          'dpop': dpopHeader
        }
      });

      if (!authorizationServer) {
        return res.status(500).json({ error: 'Authorization server not ready' });
      }

      const jwtClaims = await oauth.validateJwtAccessToken(
        authorizationServer,
        request,
        audience
      );

      // Analyze DPoP binding
      const hasCnfClaim = jwtClaims.cnf && jwtClaims.cnf.jkt;
      let cnfValidation = null;
      
      if (hasCnfClaim) {
        try {
          const dpopProofHeader = jose.decodeProtectedHeader(dpopHeader);
          const actualThumbprint = await jose.calculateJwkThumbprint(dpopProofHeader.jwk, 'sha256');
          
          cnfValidation = {
            expectedThumbprint: jwtClaims.cnf.jkt,
            actualThumbprint: actualThumbprint,
            valid: jwtClaims.cnf.jkt === actualThumbprint
          };
        } catch (cnfError) {
          cnfValidation = {
            error: cnfError.message,
            valid: false
          };
        }
      }

      const dpopDiagnostics = {
        validatedBy: 'oauth4webapi',
        tokenBound: hasCnfClaim,
        cnfClaim: hasCnfClaim ? jwtClaims.cnf : null,
        cnfValidation: cnfValidation,
        auth0Config: hasCnfClaim ? 'DPoP enabled' : 'DPoP disabled (Token Sender-Constraining = None)'
      };

      req.auth = jwtClaims;
      req.dpopDiagnostics = dpopDiagnostics;
      next();

    } catch (error) {
      console.error(`[${serverName}] DPoP validation failed:`, error.message);
      
      let errorDetails = {
        message: error.message,
        validatedBy: 'oauth4webapi'
      };
      
      if (error.cause) {
        errorDetails.cause = error.cause;
      }
      
      if (error.message && error.message.includes('JWT "cnf" (confirmation) claim missing')) {
        return res.status(401).json({
          error: 'DPoP token missing cnf claim',
          details: errorDetails,
          auth0ConfigurationIssue: {
            problem: 'Token Sender-Constraining is set to "None"',
            solution: 'Enable DPoP in Auth0 Dashboard',
            steps: [
              '1. Go to Auth0 Dashboard → APIs → Select your API',
              '2. Find "Token Sender-Constraining" setting',
              '3. Change from "None" to "Demonstrating Proof-of-Possession (DPoP)"',
              '4. Save changes and test again'
            ],
            technicalExplanation: 'Auth0 is issuing regular access tokens without the "cnf" (confirmation) claim required for DPoP binding.',
            learnMore: 'https://auth0.com/docs/secure/tokens/token-binding/configure-token-binding'
          },
          validation: {
            hasAuthorizationHeader: true,
            hasDpopHeader: true,
            tokenFormat: 'valid',
            issue: 'missing_cnf_claim'
          }
        });
      }
      
      return res.status(401).json({
        error: 'DPoP validation failed',
        details: errorDetails
      });
    }
  };

  // Routes with configurable authentication method
  const useDPoP = forceDpop !== null ? forceDpop : (process.env.USE_DPOP === 'true');
  
  if (useDPoP) {
    app.get('/api/shows', apiLimiter, checkDpop, (req, res) => {
      res.send({
        msg: `Your DPoP access token was successfully validated for ${audience}!`,
        dpopEnabled: true,
        serverAudience: audience,
        serverName: serverName,
        claims: req.auth,
        dpopDiagnostics: req.dpopDiagnostics,
        tokenBinding: {
          hasCnfClaim: req.dpopDiagnostics.tokenBound,
          auth0Config: req.dpopDiagnostics.auth0Config,
          cnfValidation: req.dpopDiagnostics.cnfValidation,
          validationMethod: 'oauth4webapi'
        }
      });
    });
  } else {
    app.get('/api/shows', apiLimiter, checkJwt, (req, res) => {
      res.send({
        msg: `Your Bearer access token was successfully validated for ${audience}!`,
        dpopEnabled: false,
        serverAudience: audience,
        serverName: serverName,
        claims: req.auth,
        tokenBinding: {
          hasCnfClaim: false,
          auth0Config: 'DPoP disabled',
          validationMethod: 'express-jwt'
        }
      });
    });
  }

  // Bearer token endpoint for comparison
  app.get('/api/shows-bearer', apiLimiter, checkJwt, (req, res) => {
    res.send({
      msg: `Your Bearer access token was successfully validated for ${audience}!`,
      dpopEnabled: false,
      authType: 'Bearer',
      serverAudience: audience,
      serverName: serverName,
      claims: req.auth,
      tokenBinding: {
        hasCnfClaim: false,
        auth0Config: 'Bearer tokens (no DPoP binding)',
        validationMethod: 'express-jwt'
      }
    });
  });

  return app;
}

// Main server startup function
async function startServers() {
  try {
    await initializeAuthorizationServer();

    // Server configurations
    const servers = [
      // {
      //   audience: process.env.AUTH0_BEARER_AUDIENCE || 'resource-server-1',
      //   port: 3002,
      //   name: 'Bearer-Server',
      //   forceDpop: false
      // },
      {
        audience: process.env.AUTH0_DPOP_AUDIENCE || 'https://example.com',
        port: 3001,
        name: 'DPoP-Server',
        forceDpop: true
      }
    ];

    // Start both servers
    for (const config of servers) {
      const app = createApiServer(config.audience, config.name, config.forceDpop);
      const availablePort = await findAvailablePort(config.port);
      
      const server = app.listen(availablePort, () => {
        console.log(`[${config.name}] API Server listening on port ${availablePort}`);
        console.log(`[${config.name}] Audience: ${config.audience}`);
        console.log(`[${config.name}] Auth Method: ${config.forceDpop ? 'DPoP' : 'Bearer'}`);
      });

      process.on('SIGINT', () => server.close());
    }

  } catch (error) {
    console.error('Failed to start API servers:', error);
    process.exit(1);
  }
}

startServers();
