import { createServer as createHttpServer, IncomingMessage, Server, ServerResponse } from 'http';
import { NextApiRequest, NextApiResponse } from 'next';
import * as qs from 'querystring';
import * as cookie from 'cookie';
import { AddressInfo } from 'net';
import { parseJson } from '../auth0-session/fixtures/server';

let server: Server;

const toNextApiRequest = async (req: IncomingMessage): Promise<NextApiRequest> => {
  const parsedReq = await parseJson(req, new ServerResponse(req));
  const apiReq = parsedReq as NextApiRequest;
  apiReq.query = qs.parse(new URL(req.url!, 'http://example.com').search.slice(1));
  apiReq.cookies = cookie.parse((req.headers.cookie as string) || '');
  return apiReq;
};

const toNextApiResponse = async (res: ServerResponse): Promise<NextApiResponse> => {
  const apiRes = res as NextApiResponse;

  apiRes.status = (statusCode) => {
    apiRes.statusCode = statusCode;
    return apiRes;
  };
  apiRes.send = apiRes.end.bind(apiRes);
  apiRes.json = (data) => {
    apiRes.setHeader('Content-Type', 'application/json; charset=utf-8');
    apiRes.send(JSON.stringify(data));
  };
  apiRes.redirect = (statusOrUrl: string | number, url?: string) => {
    if (typeof statusOrUrl === 'string') {
      url = statusOrUrl;
      statusOrUrl = 307;
    }
    apiRes.writeHead(statusOrUrl, { Location: url });
    apiRes.write(url);
    apiRes.end();
    return apiRes;
  };

  return apiRes;
};

const handle = async (req: NextApiRequest, res: NextApiResponse) => {
  const [path] = req.url!.split('?');
  if (path.startsWith('/api/auth')) {
    req.query.auth0 = path.split('/').slice(3);
    await (global.handleAuth?.())(req, res);
    return;
  }
  switch (path) {
    case '/api/access-token':
      {
        try {
          const json = await global.getAccessToken?.(req, res);
          res.status(200).json(json);
        } catch (error) {
          res.statusMessage = error.message;
          res.status(error.status || 500).end(error.message);
        }
      }
      break;
    case '/api/protected':
      {
        (
          await global.withApiAuthRequired?.(function protectedApiRoute() {
            res.status(200).json({ foo: 'bar' });
          })
        )(req, res);
      }
      break;
    case '/api/session':
      {
        const json = await global.getSession?.(req, res);
        res.status(200).json(json);
      }
      break;
    case '/api/touch-session':
      {
        await global.touchSession?.(req, res);
        const json = await global.getSession?.(req, res);
        res.status(200).json(json);
      }
      break;
    case '/api/update-session':
      {
        const session = await global.getSession?.(req, res);
        const updated = { ...session, ...req.body?.session };
        await global.updateSession?.(req, res, updated);
        res.status(200).json(updated);
      }
      break;
    case '/protected':
      const ret = await global.withPageAuthRequired?.()({ req, res, resolvedUrl: path });
      if (ret.redirect) {
        res.redirect(ret.redirect.destination);
      } else {
        const user = (await ret.props).user;
        res.send(`<div>Protected Page ${user ? user.sub : ''}</div>`);
      }
      break;
    default:
      res.status(418).end();
      return;
  }
};

export const start = async (): Promise<string> => {
  server = createHttpServer(async (req, res) => {
    const apiReq = await toNextApiRequest(req);
    const apiRes = await toNextApiResponse(res);
    await handle(apiReq, apiRes);
  });
  const port = await new Promise((resolve) => server.listen(0, () => resolve((server.address() as AddressInfo).port)));
  return `http://localhost:${port}`;
};

export const stop = async (): Promise<void> => {
  await new Promise((resolve) => server.close(resolve as (err?: Error) => {}));
};
