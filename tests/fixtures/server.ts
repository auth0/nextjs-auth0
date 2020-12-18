import { createServer as createHttpServer, Server } from 'http';
import next from 'next';
import path from 'path';
import { parse } from 'url';
import { AddressInfo } from 'net';

let server: Server;

export const start = async (): Promise<string> => {
  const app = next({ dev: false, dir: path.join(__dirname, 'test-app') });
  await app.prepare();
  const handle = app.getRequestHandler();
  server = createHttpServer(async (req, res) => {
    const parsedUrl = parse(req.url as string, true);
    await handle(req, res, parsedUrl);
  });
  const port = await new Promise((resolve) => server.listen(0, () => resolve((server.address() as AddressInfo).port)));
  return `http://localhost:${port}`;
};

export const stop = async (): Promise<void> => {
  await new Promise((resolve) => server.close(resolve as (err?: Error) => {}));
};
