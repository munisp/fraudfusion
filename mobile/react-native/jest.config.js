module.exports = {
  preset: 'react-native',
  testMatch: ['<rootDir>/src/**/*.test.ts', '<rootDir>/src/**/*.test.tsx'],
  setupFilesAfterEnv: ['<rootDir>/jest.setup.js'],
  transformIgnorePatterns: [
    'node_modules/(?!(@react-native|react-native|@react-navigation|@notifee|@react-native-firebase)/)',
  ],
  clearMocks: true,
  restoreMocks: true,
  collectCoverage: true,
  collectCoverageFrom: ['<rootDir>/src/screens/**/*.tsx', '!<rootDir>/src/screens/**/*.test.tsx', '!<rootDir>/src/screens/LoginScreen.tsx'],
  coverageThreshold: {
    global: { branches: 100, functions: 100, lines: 100, statements: 100 },
  },
};
