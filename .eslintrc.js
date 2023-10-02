module.exports = {
  extends: ['airbnb-base', 'prettier', 'plugin:jest/recommended'],
  env: {
    browser: true,
    node: true,
    mocha: true,
    'jest/globals': true,
  },
  plugins: ['prettier', 'jest'],
  rules: {
    'class-methods-use-this': 0,
    'import/no-extraneous-dependencies': ['error', { devDependencies: true }],
    'prettier/prettier': ['error'],
    'no-underscore-dangle': 'off',
    'import/extensions': 'off',
  },
  parser: '@babel/eslint-parser',
};
