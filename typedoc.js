module.exports = {
  name: '"@auth0/nextjs-auth0',
  out: './docs/',
  mode: 'file',
  exclude: [
    './src/auth0-session/**',
    './src/session/cache.ts',
    './src/utils/!(errors.ts)',
    './src/index.ts',
    './src/index.browser.ts'
  ],
  excludeExternals: true,
  excludePrivate: true,
  excludeNotExported: true,
  includeDeclarations: true,
  hideGenerator: true,
  theme: 'minimal',
  readme: 'none'
};
