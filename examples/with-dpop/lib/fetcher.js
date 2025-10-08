/**
 * Server-side and client-side fetcher utilities for DPoP authentication
 *
 * This demonstrates the server-side createFetcher functionality for advanced
 * configuration scenarios including custom base URLs and enhanced logging.
 */

import { auth0 } from './auth0';
import { createFetcher } from '@auth0/nextjs-auth0/server';

/**
 * Custom fetch implementation with enhanced logging for demonstration
 */
const customFetchWithLogging = async (url, options) => {
  const start = Date.now();
  console.info(`[CustomFetch] Making DPoP request to: ${url}`);
  console.info(`[CustomFetch] Request method: ${options?.method || 'GET'}`);
  console.info(`[CustomFetch] Request headers:`, {
    authorization: options?.headers?.Authorization ? 'Bearer [REDACTED]' : 'None',
    dpop: options?.headers?.DPoP ? 'DPoP [PRESENT]' : 'None',
    contentType: options?.headers?.['Content-Type'] || 'None'
  });

  try {
    const response = await fetch(url, options);
    const duration = Date.now() - start;

    console.info(`[CustomFetch] Request completed in ${duration}ms`);
    console.info(`[CustomFetch] Response status: ${response.status} ${response.statusText}`);
    console.info(`[CustomFetch] Response headers:`, {
      contentType: response.headers.get('content-type') || 'None',
      contentLength: response.headers.get('content-length') || 'Unknown'
    });

    return response;
  } catch (error) {
    const duration = Date.now() - start;
    console.error(`[CustomFetch] Request failed after ${duration}ms:`, error.message);
    throw error;
  }
};

/**
 * Create a basic server-side fetcher with base URL configuration
 * This demonstrates the simplest server-side createFetcher usage
 */
export const createApiServerFetcher = () => {
  const apiPort = process.env.API_PORT || 3001;
  return createFetcher(auth0, {
    baseUrl: `http://localhost:${apiPort}`
  });
};

/**
 * Create an enhanced server-side fetcher with custom fetch implementation
 * This demonstrates advanced configuration with logging and metrics
 */
export const createEnhancedApiServerFetcher = () => {
  const apiPort = process.env.API_PORT || 3001;
  return createFetcher(auth0, {
    baseUrl: `http://localhost:${apiPort}`,
    fetch: customFetchWithLogging
  });
};

/**
 * Create a production-ready server-side fetcher
 * This demonstrates environment-specific configuration
 */
export const createProductionApiServerFetcher = () => {
  const apiPort = process.env.API_PORT || 3001;
  const isDevelopment = process.env.NODE_ENV === 'development';

  return createFetcher(auth0, {
    baseUrl: `http://localhost:${apiPort}`,
    // Use enhanced logging only in development
    fetch: isDevelopment ? customFetchWithLogging : undefined
  });
};