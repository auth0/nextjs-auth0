const app = require('express')();
const cors = require('cors');
const dotenv = require('dotenv');
const jwt = require('express-jwt');
const jwksRsa = require('jwks-rsa');
const fetch = require('isomorphic-unfetch');

// Load settings from the .env file
dotenv.config();

// Allow all cors, not recommended for production.
app.use(cors());

// Require access tokens.
const requireAuth = jwt({
  secret: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
    jwksUri: `https://${process.env.AUTH0_DOMAIN}/.well-known/jwks.json`
  }),

  audience: process.env.AUTH0_API_IDENTIFIER,
  issuer: `https://${process.env.AUTH0_DOMAIN}/`,
  algorithms: ['RS256']
});

/**
 * This endpoint is open to all.
 */
app.get('/api/shows', (req, res) => {
  fetch('https://api.tvmaze.com/shows')
    .then((r) => r.json())
    .then((shows) => {
      res.send({
        shows
      });
    })
    .catch((err) =>
      res.status(500).send({
        error: err.message
      })
    );
});

/**
 * This endpoint requires authentication.
 */
app.get('/api/my/shows', requireAuth, (req, res) => {
  fetch('https://api.tvmaze.com/search/shows?q=identity')
    .then((r) => r.json())
    .then((shows) => {
      res.send({
        shows
      });
    })
    .catch((err) =>
      res.status(500).send({
        error: err.message
      })
    );
});

const port = process.env.PORT || 3001;
app.listen(port, () => console.log(`Sample API listening on http://localhost:${port}`));
