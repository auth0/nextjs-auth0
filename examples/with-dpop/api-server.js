/**
 * ⚠️ EXAMPLE ONLY - NOT FOR PRODUCTION USE ⚠️
 * 
 * This is a demonstration API server for testing DPoP functionality.
 * 
 * SECURITY WARNINGS:
 * - This code is for development/testing purposes only
 * - CodeQL security scanner correctly flags several issues that are acceptable for examples:
 *   * User-controlled security bypass (USE_DPOP env var) - intentional for demo switching
 *   * Log injection from headers - acceptable for debugging in non-production
 *   * Missing rate limiting on some routes - should be added for production
 * - DO NOT deploy this code to production without proper hardening
 * - For production use, implement proper:
 *   * Input validation and sanitization
 *   * Rate limiting on all endpoints
 *   * Structured logging (not console.log)
 *   * Environment variable validation
 *   * Error handling without information leakage
 */

require('dotenv').config({ path: './.env.local' });

const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { expressjwt: jwt } = require('express-jwt');
const jwksRsa = require('jwks-rsa');
const oauth = require('oauth4webapi');
const crypto = require('crypto');
const jose = require('jose');

const app = express();
const port = process.env.API_PORT || 3001;
const baseUrl = process.env.APP_BASE_URL;
const domain = process.env.AUTH0_DOMAIN;
const issuerBaseUrl = `https://${domain}`;
const audience = process.env.AUTH0_AUDIENCE;

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

// Rate limiting configuration
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

let authorizationServer;

async function initializeAuthorizationServer() {
  try {
    console.log('[API] Discovering authorization server metadata...');
    console.log('[API] Issuer URL:', issuerBaseUrl);
    
    const issuer = new URL(issuerBaseUrl);
    const discoveryResponse = await oauth.discoveryRequest(issuer, {
      [oauth.allowInsecureRequests]: process.env.NODE_ENV === 'development'
    });
    
    authorizationServer = await oauth.processDiscoveryResponse(issuer, discoveryResponse);
    
    console.log('[API] Authorization server metadata discovered successfully');
    console.log('[API] Issuer:', authorizationServer.issuer);
    console.log('[API] JWKS URI:', authorizationServer.jwks_uri);
    console.log('[API] Token endpoint:', authorizationServer.token_endpoint);
    
  } catch (error) {
    console.error('[API] Failed to discover authorization server metadata:', error);
    
    console.log('[API] Using fallback authorization server configuration...');
    authorizationServer = {
      issuer: issuerBaseUrl,
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
// This middleware validates DPoP proofs according to RFC 9449
const checkDpop = async (req, res, next) => {
  console.log('[API] DPoP validation middleware called');
  console.log('[API] Request headers:', {
    authorization: req.headers.authorization ? 'Present' : 'Missing',
    dpop: req.headers.dpop ? 'Present' : 'Missing',
    contentType: req.headers['content-type'] || 'N/A',
    userAgent: req.headers['user-agent'] || 'N/A'
  });
  
  console.log('[API] Starting DPoP validation process');

  try {
    // Step 1: Validate request has proper headers
    console.log('[API] Step 1: Validating headers');
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      console.log('[API] Missing Authorization header');
      return res.status(401).json({ error: 'Missing Authorization header' });
    }

    // Check if using DPoP scheme
    if (!authHeader.toLowerCase().startsWith('dpop ')) {
      console.log('[API] Invalid authorization scheme, expected DPoP');
      return res.status(401).json({ error: 'Expected DPoP authorization scheme' });
    }

    const dpopHeader = req.headers.dpop;
    if (!dpopHeader) {
      console.log('[API] Missing DPoP header');
      return res.status(401).json({ error: 'Missing DPoP header' });
    }

    const accessToken = authHeader.slice(5); // Remove 'DPoP ' prefix
    console.log('[API] Headers validated successfully');

    // Step 2: Validate JWT access token using jose (Auth0 compatible)
    console.log('[API] Step 2: Validating JWT access token');
    
    // Use discovered JWKS URI from authorization server metadata
    const jwksUri = authorizationServer?.jwks_uri || `${issuerBaseUrl}/.well-known/jwks.json`;
    const jwks = jose.createRemoteJWKSet(new URL(jwksUri));

    // Verify JWT access token using jose with discovered issuer
    const expectedIssuer = authorizationServer?.issuer || `${issuerBaseUrl}/`;
    const { payload: jwtClaims } = await jose.jwtVerify(accessToken, jwks, {
      audience: audience,
      issuer: expectedIssuer,
      algorithms: ['RS256']
    });
    console.log('[API] JWT access token validated successfully');

    // Step 3: Validate DPoP proof
    console.log('[API] Step 3: Validating DPoP proof');

    // Parse DPoP proof JWT
    const dpopProofHeader = jose.decodeProtectedHeader(dpopHeader);
    const dpopProofPayload = jose.decodeJwt(dpopHeader);
    
    console.log('[API] DPoP proof parsed successfully');
    
    if (!dpopProofHeader || !dpopProofPayload) {
      console.log('[API] Invalid DPoP proof format');
      return res.status(401).json({ error: 'Invalid DPoP proof format' });
    }
    
    // Check required DPoP proof headers
    if (dpopProofHeader.typ !== 'dpop+jwt') {
      console.log('[API] Invalid DPoP proof typ');
      return res.status(401).json({ error: 'DPoP proof must have typ: dpop+jwt' });
    }

    if (!dpopProofHeader.alg) {
      console.log('[API] Missing DPoP proof alg header');
      return res.status(401).json({ error: 'DPoP proof missing alg header' });
    }

    if (!dpopProofHeader.jwk) {
      console.log('[API] Missing DPoP proof jwk header');
      return res.status(401).json({ error: 'DPoP proof missing jwk header' });
    }

    // Check required DPoP proof claims
    console.log('[API] Validating DPoP proof claims');
    if (dpopProofPayload.htm !== req.method) {
      console.log('[API] DPoP proof htm mismatch');
      return res.status(401).json({ error: 'DPoP proof htm mismatch' });
    }

    const expectedHtu = `${req.protocol}://${req.get('host')}${req.originalUrl.split('?')[0]}`;
    console.log('[API] Validating HTU claim');
    if (dpopProofPayload.htu !== expectedHtu) {
      console.log('[API] URL mismatch in DPoP proof');
      return res.status(401).json({ error: 'DPoP proof htu mismatch' });
    }

    // Validate access token hash (ath) claim
    const expectedAth = crypto.createHash('sha256').update(accessToken).digest('base64url');
    console.log('[API] Validating access token hash');
    if (dpopProofPayload.ath !== expectedAth) {
      console.log('[API] Access token hash mismatch');
      return res.status(401).json({ error: 'DPoP proof ath mismatch' });
    }

    // Validate timestamp - DPoP proofs should be recent (within 5 minutes)
    const now = Math.floor(Date.now() / 1000);
    const timeDiff = Math.abs(now - dpopProofPayload.iat);
    console.log('[API] Validating DPoP proof timestamp');
    if (timeDiff > 300) {
      console.log('[API] DPoP proof timestamp validation failed');
      return res.status(401).json({ error: 'DPoP proof is not recent enough' });
    }

    // Validate DPoP proof signature using jose library
    console.log('[API] Step 4: Validating DPoP proof signature');
    try {
      // Determine algorithm for importJWK
      let alg = dpopProofHeader.alg;
      if (!alg) {
        // Try to infer from JWK
        const jwk = dpopProofHeader.jwk;
        if (jwk.kty === 'EC' && jwk.crv === 'P-256') {
          alg = 'ES256';
        } else if (jwk.kty === 'RSA') {
          alg = 'RS256';
        } else {
          console.error('[API] Unable to determine JWK algorithm for DPoP proof');
          return res.status(401).json({ error: 'Unable to determine JWK algorithm for DPoP proof' });
        }
      }
      console.log('[API] Using algorithm:', alg);
      const publicKey = await jose.importJWK(dpopProofHeader.jwk, alg);
      await jose.jwtVerify(dpopHeader, publicKey, {
        typ: 'dpop+jwt'
      });
      console.log('[API] DPoP proof signature successfully verified');
    } catch (err) {
      console.error('[API] DPoP signature validation error');
      return res.status(401).json({ error: 'DPoP proof signature validation failed' });
    }

    // Attach validated claims to request for use in route handlers
    req.auth = jwtClaims;
    req.dpopProof = dpopProofPayload;
    console.log('[API] DPoP validation completed successfully');
    next();
  } catch (error) {
    console.error('[API] DPoP validation failed');
    return res.status(401).json({
      error: 'DPoP validation failed'
    });  
  }
};

// Apply middleware based on DPoP configuration
// Routes are protected with rate limiting and authentication
if (process.env.USE_DPOP === 'true') {
  app.get('/api/shows', apiLimiter, checkDpop, (req, res) => {
    console.log('[API] DPoP endpoint hit successfully');
    res.send({
      msg: 'Your DPoP access token was successfully validated!',
      dpopEnabled: true,
      claims: req.auth
    });
  });
} else {
  app.get('/api/shows', apiLimiter, checkJwt, (req, res) => {
    console.log('[API] Bearer token endpoint hit successfully');
    res.send({
      msg: 'Your access token was successfully validated!',
      dpopEnabled: false
    });
  });
}

// Start server with dynamic port assignment
async function startServer() {
  try {
    await initializeAuthorizationServer();
    const availablePort = await findAvailablePort(port);
    
    const server = app.listen(availablePort, () => {
      console.log(`API Server listening on port ${availablePort}`);
      console.log(`DPoP validation: ${process.env.USE_DPOP === 'true' ? 'ENABLED' : 'DISABLED'}`);
    });

    process.on('SIGINT', () => server.close());
  } catch (error) {
    console.error('Failed to start API server:', error);
    process.exit(1);
  }
}

startServer();
