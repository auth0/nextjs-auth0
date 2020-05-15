import crypto from 'crypto';
import { AddressInfo } from 'net';
import { parse as parseUrl } from 'url';
import { parse as parseQs } from 'querystring';
import { NextApiRequest, NextApiResponse } from 'next';
import { IncomingMessage, ServerResponse, Server, createServer } from 'http';
import { apiResolver, ApiError } from 'next/dist/next-server/server/api-utils';

interface IHandler {
  (req: NextApiRequest, res: NextApiResponse): Promise<void>;
}

export default class HttpServer {
  private handler: IHandler;

  private httpServer: Server;

  constructor(handler: IHandler) {
    this.handler = handler;
    this.httpServer = createServer((req: IncomingMessage, res: ServerResponse) => {
      if (!req.url) {
        throw new Error('No url provided');
      }

      const parsedUrl = parseUrl(req.url);
      const parsedQuery = (parsedUrl.query && parseQs(parsedUrl.query)) || {};

      const previewMode = {
        previewModeId: crypto.randomBytes(16).toString('hex'),
        previewModeSigningKey: crypto.randomBytes(32).toString('hex'),
        previewModeEncryptionKey: crypto.randomBytes(32).toString('hex')
      };

      apiResolver(req, res, parsedQuery, this.handleRequest(), previewMode);
    });
  }

  setHandler(handler: IHandler): void {
    this.handler = handler;
  }

  handleRequest = () => async (req: NextApiRequest, res: NextApiResponse): Promise<void> => {
    try {
      await this.handler(req, res);
    } catch (err) {
      if (err instanceof ApiError) {
        res.statusCode = err.statusCode;
        res.end(err.message);
      } else {
        res.statusCode = 500;
        res.end(err.message);
      }
    }
  };

  start(done?: () => void): Promise<void> {
    return new Promise((resolve) => {
      this.httpServer.listen(() => {
        if (done) {
          done();
        }

        resolve();
      });
    });
  }

  stop(done: (err?: Error) => void): void {
    this.httpServer.close(done);
  }

  getUrl(): string {
    const { address, port } = this.httpServer.address() as AddressInfo;
    return `http://${address}:${port}`;
  }
}
