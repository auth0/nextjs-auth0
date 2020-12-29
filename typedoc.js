module.exports = {
  name: '@auth0/nextjs-auth0 (Beta Only)',
  out: './docs/',
  exclude: [
    './src/auth0-session/**',
    './src/session/cache.ts',
    './src/utils/!(errors.ts)',
    './src/index.ts',
    './src/index.browser.ts'
  ],
  excludeExternals: true,
  excludePrivate: true,
  hideGenerator: true,
  readme: 'none'
};
