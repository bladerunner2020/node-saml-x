module.exports = {
  root: true,
  env: {
    node: true,
    es6: true
  },
  extends: 'eslint:recommended',
  parserOptions: {
    ecmaVersion: 2018
  },
  rules: {
    'no-undefined': 'off',
    'no-unused-vars': 'error',
    'no-throw-literal': 'error',
    quotes: ['warn', 'single'],
    curly: 'error',
    semi: [
      'error',
      'always'
    ]
  }
};
