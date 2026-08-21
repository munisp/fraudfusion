module.exports = {
  root: true,
  extends: ['@react-native'],
  parser: '@typescript-eslint/parser',
  plugins: ['@typescript-eslint'],
  env: {
    'react-native/react-native': true,
    jest: true,
  },
  rules: {
    'no-console': ['error', { allow: [] }],
    '@typescript-eslint/no-explicit-any': 'error',
    '@typescript-eslint/no-floating-promises': 'error',
  },
  overrides: [
    {
      files: ['src/services/logger.ts'],
      rules: {
        'no-console': 'off',
      },
    },
  ],
};
