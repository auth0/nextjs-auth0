import SessionCache from './cache';

/**
 * Get the user's session from the request.
 *
 * @category Server
 */
export type GetSessionCache = () => SessionCache | null | undefined;

/**
 * @ignore
 */
export default function sessionCacheFactory(sessionCache: SessionCache): GetSessionCache {
  return (): SessionCache => {
    return sessionCache;
  };
}
