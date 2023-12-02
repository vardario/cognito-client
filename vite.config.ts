import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    exclude: ['lib/**/*', 'node_modules', 'cognito-deployment/**/*'],
    hookTimeout: 60000,
    testTimeout: 60000
  }
});
