import '@testing-library/jest-dom';
import { TextEncoder, TextDecoder } from 'util';

// Polyfill for TextEncoder/TextDecoder in Node.js environment
if (typeof global.TextEncoder === 'undefined') {
  global.TextEncoder = TextEncoder;
}
if (typeof global.TextDecoder === 'undefined') {
  global.TextDecoder = TextDecoder;
}

// Mock fetch if not available
if (typeof global.fetch === 'undefined') {
  global.fetch = vi.fn();
}

// Mock environment variables
process.env.AUTH0_DOMAIN = 'test-domain.auth0.com';
process.env.AUTH0_CLIENT_ID = 'test-client-id';
process.env.AUTH0_CLIENT_SECRET = 'test-client-secret';
process.env.AUTH0_ISSUER_BASE_URL = 'https://test-domain.auth0.com';
process.env.AUTH0_SECRET = 'test-secret-key-that-is-long-enough';
process.env.AUTH0_AUDIENCE = 'https://test-domain.auth0.com/api/v2/';
process.env.USE_DPOP = 'true';

// Mock fetch globally
global.fetch = vi.fn();

// Mock next/server
vi.mock('next/server', () => ({
  NextResponse: {
    json: vi.fn((data, init) => ({
      json: () => Promise.resolve(data),
      status: init?.status || 200,
      headers: new Map(),
      ok: (init?.status || 200) < 400
    }))
  }
}));
