require('dotenv').config();
const app = require('express')();
const cors = require('cors');
const { auth, requiredScopes } = require('express-oauth2-bearer');
const fetch = require('isomorphic-unfetch');

// Allow all cors, not recommended for production.
app.use(cors());

app.use(auth());

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
app.get('/api/my/shows', requiredScopes('read:shows'), (req, res) => {
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
