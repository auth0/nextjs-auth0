module.exports = {
  env: {
    browser: true,
    es6: true,
    node: true
  },
  settings: {
    react: {
      version: 'detect'
    }
  },
  extends: [
    'eslint:recommended',
    'plugin:react/recommended',
    'plugin:@typescript-eslint/eslint-recommended'
  ],
  parser: '@typescript-eslint/parser',
  parserOptions: {
    ecmaFeatures: {
      jsx: true
    },
    ecmaVersion: 2018,
    sourceType: 'module'
  },
  plugins: ['react', 'react-hooks'],
  rules: {
    'prettier/prettier': 'off', // like having an over-curious mom when you're a teenager
    'spaced-comment': 'off',
    'comma-dangle': 'off',
    'no-multi-assign': 'off',
    'max-len': 'off',
    indent: ['warn', 2, { SwitchCase: 1 }],
    'linebreak-style': ['error', 'unix'],
    'no-unused-vars': 'off',
    'react/react-in-jsx-scope': 'off',
    'react-hooks/rules-of-hooks': 'error',
    'react-hooks/exhaustive-deps': 'warn',
    semi: ['warn', 'never'],
    '@typescript-eslint/semi': ['off'],
    "@typescript-eslint/explicit-function-return-type": ["off"],
    "@typescript-eslint/ban-ts-ignore": "off"
  }
}
