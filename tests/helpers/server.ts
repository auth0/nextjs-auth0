import { AddressInfo } from 'net';
import { IncomingMessage, ServerResponse, createServer, Server } from 'http';

interface IHandler {
  (req: IncomingMessage, res: ServerResponse): Promise<void>;
}

export default class HttpServer {
  private handler: IHandler;

  private httpServer: Server;

  constructor(handler: IHandler) {
    this.handler = handler;
    this.httpServer = createServer((req: IncomingMessage, res: ServerResponse) => {
      this.handler(req, res).catch((e) => {
        res.statusCode = 500;
        res.end(e.message);
      });
    });
  }

  setHandler(handler: IHandler): void {
    this.handler = handler;
  }

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
