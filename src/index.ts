/* eslint-disable */
import IAuth0Settings from './settings';
import { ISignInWithAuth0 } from './instance';

export function useAuth0(settings: IAuth0Settings): ISignInWithAuth0 {
  const isBrowser = typeof window !== 'undefined' || (process as any).browser;
  if (isBrowser) {
    return require('./instance.browser').default(settings); // eslint-disable-line
  }

  return require('./instance.node').default(settings);
};

export function withAuth0(nextConfig: any = {}): any {
  return Object.assign({}, nextConfig, {
    webpack(config: any, { isServer }: { isServer: boolean }): any {
      if (!isServer) {
        config.externals = ['openid-client'];
      }

      return config;
    }
  });
};
