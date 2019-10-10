import { Socket } from 'net';
import { IncomingMessage, ServerResponse } from 'http';

export interface IHttpHelpers {
  req: any;
  res: any;
  setHeaderFn: jest.Mock;
  jsonFn: jest.Mock;
  statusFn: jest.Mock;
}

export default function getRequestResponse(): IHttpHelpers {
  const req: IncomingMessage = new IncomingMessage(
    new Socket()
  );
  req.headers = {
    host: 'localhost'
  };

  const res: any = new ServerResponse(req);
  res.setHeader = jest.fn();
  res.json = jest.fn();
  res.status = jest.fn(() => res);

  return {
    req,
    res,
    setHeaderFn: res.setHeader,
    jsonFn: res.json,
    statusFn: res.status
  };
}
