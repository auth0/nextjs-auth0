import { auth0 } from '@/lib/auth0';

/**
 * SDK catch-all route handler.
 * 
 * Handles all Auth0 SDK routes:
 * - /auth/login
 * - /auth/logout  
 * - /auth/callback
 * - /auth/profile
 * - /auth/mfa/* (MFA operations)
 * - etc.
 */
export const GET = auth0.handler;
export const POST = auth0.handler;
export const DELETE = auth0.handler;
