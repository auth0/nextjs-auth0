"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
function useAuth0(settings) {
    const isBrowser = typeof window !== 'undefined' || process.browser;
    if (isBrowser) {
        return require('./instance.browser').default(settings);
    }
    return require('./instance.node').default(settings);
}
exports.useAuth0 = useAuth0;
;
function withAuth0(nextConfig = {}, options = {}) {
    return Object.assign({}, nextConfig, {
        webpack(config, { isServer }) {
            if (!isServer) {
                config.externals = ['openid-client'];
            }
            if (typeof nextConfig.webpack === 'function') {
                return nextConfig.webpack(config, options);
            }
            return config;
        }
    });
}
exports.withAuth0 = withAuth0;
;
//# sourceMappingURL=index.js.map