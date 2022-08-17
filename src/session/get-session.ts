import { IncomingMessage } from 'http';
import { NextApiRequest } from 'next';
import { Session } from '../session';
import { NextRequest } from 'next/server';

/**
 * Get the user's session from the request.
 *
 * @category Server
 */
export type NodeGetSession = (req: IncomingMessage | NextApiRequest) => Session | null | undefined;
export type MiddlewareGetSession = (req: NextRequest) => Session | null | undefined;
