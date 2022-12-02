module.exports = {
  name: '@auth0/nextjs-auth0',
  out: './docs/',
  exclude: [
    './src/auth0-session/**',
    './src/session/cache.ts',
    './src/client/use-config.tsx',
    './src/utils/!(errors.ts)'
  ],
  excludeExternals: true,
  excludePrivate: true,
  hideGenerator: true,
  readme: 'none'
};
