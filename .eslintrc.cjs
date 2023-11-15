module.exports = {
  extends: ['eslint:recommended', 'plugin:@typescript-eslint/recommended', 'prettier'],
  plugins: ['@typescript-eslint', 'unused-imports'],
  ignorePatterns: [
    '*.cjs',
    'jest.*.ts',
    '/dist',
    '**/cdk.out/*',
    '**/build/*',
    'pnpm-*.yaml',
    '*.sql',
    '*.sh',
    '*.png',
    '*.svg',
    '*.jpg',
    '*.jpeg',
    '*.csv',
    '*.ttf',
    '*.postcss',
    '*.html'
  ],
  overrides: [],
  parserOptions: {
    sourceType: 'module',
    ecmaVersion: 2021
  },
  rules: {
    '@typescript-eslint/no-explicit-any': 'off',
    '@typescript-eslint/no-non-null-assertion': 'off',
    'turbo/no-undeclared-env-vars': 'off',
    'unused-imports/no-unused-imports-ts': 'error',
    '@typescript-eslint/no-unused-vars': [
      'warn',
      { vars: 'all', varsIgnorePattern: '^_', args: 'after-used', argsIgnorePattern: '^_' }
    ]
  },
  env: {
    browser: true,
    es2022: true,
    node: true
  },
  globals: {
    $$Generic: 'readonly'
  }
};
