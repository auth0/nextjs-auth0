const express = require('express');
const next = require('next');
const oidc = require('../scripts/oidc-provider');

const port = +(process.env.PORT || 3000);
const app = next({ dev: true, hostname: 'localhost', port });
const handle = app.getRequestHandler();

process.env.AUTH0_ISSUER_BASE_URL = `http://localhost:${port}/oidc/`;
process.env.AUTH0_CLIENT_ID = 'testing';
process.env.AUTH0_CLIENT_SECRET = 'testing';
process.env.AUTH0_SCOPE = 'openid profile email offline_access';

app
  .prepare()
  .then(() => {
    const server = express();

    server.use('/oidc', oidc({}).callback());

    server.all('*', (req, res) => {
      return handle(req, res);
    });

    server.listen(port, (err) => {
      if (err) throw err;
      console.log(`> Ready on http://localhost:${port}`);
    });
  })
  .catch((err) => {
    console.log('Error:::::', err);
  });
