import { Buffer } from 'buffer';

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
