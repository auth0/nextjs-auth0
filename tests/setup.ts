import { Buffer } from 'buffer';
import fetch, { Headers, Request, Response } from 'node-fetch';

if (!globalThis.fetch) {
  (globalThis as any).fetch = fetch;
  (globalThis as any).Headers = Headers;
  (globalThis as any).Request = Request;
  (globalThis as any).Response = Response;
  (globalThis as any).Response.json = (data = undefined, init = {}) => {
    const body = JSON.stringify(data);

    if (body === undefined) {
      throw new TypeError('data is not JSON serializable');
    }

    const headers = new Headers(init && (init as any).headers);

    if (!headers.has('content-type')) {
      headers.set('content-type', 'application/json');
    }

    return new Response(body, {
      ...init,
      headers
    });
  };
}

if (typeof TextDecoder !== 'undefined') {
  // Monkey patch Text Decoder to workaround https://github.com/vercel/edge-runtime/issues/62
  // This can be removed when https://github.com/vercel/edge-runtime/pull/80 is merged
  const tmp = TextDecoder.prototype.decode;
  TextDecoder.prototype.decode = function (input, options) {
    if (Buffer.isBuffer(input)) {
      return tmp.call(this, new TextEncoder().encode(input.toString()), options);
    }
    return tmp.call(this, input, options);
  };
}

beforeEach(() => {
  jest.spyOn(console, 'warn').mockImplementation(() => {
    // no-op
  });
});

let mockActualReact: any;

jest.doMock('react', () => {
  if (!mockActualReact) {
    mockActualReact = jest.requireActual('react');
  }
  return mockActualReact;
});

afterEach(() => {
  jest.clearAllMocks();
  jest.restoreAllMocks();
  jest.resetModules();
});
