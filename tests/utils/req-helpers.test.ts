import { Socket } from 'net';
import { IncomingMessage } from 'http';
import { NextRequest } from 'next/server';
import { isRequest, isNextApiRequest } from '../../src/utils/req-helpers';

describe('req-helpers', () => {
  const req = new Request(new URL('http://example.com'));
  const reqNode16 = new Proxy(req, {});
  const reqNext = new NextRequest(new URL('http://example.com'));
  const nodeReq = new IncomingMessage(new Socket());
  class NextApiRequest extends IncomingMessage {
    constructor() {
      super(new Socket());
    }
    query = {};
  }
  const nextApiReq = new NextApiRequest();

  test('#isRequest', () => {
    expect(isRequest(req)).toBe(true);
    expect(isRequest(reqNode16)).toBe(true);
    expect(isRequest(reqNext)).toBe(true);
    expect(isRequest(nodeReq)).toBe(false);
    expect(isRequest(nextApiReq)).toBe(false);
  });

  test('#isNextApiRequest', () => {
    expect(isNextApiRequest(req)).toBe(false);
    expect(isNextApiRequest(reqNode16)).toBe(false);
    expect(isNextApiRequest(reqNext)).toBe(false);
    expect(isNextApiRequest(nodeReq)).toBe(false);
    expect(isNextApiRequest(nextApiReq)).toBe(true);
  });
});
