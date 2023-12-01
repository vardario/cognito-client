import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    exclude: ['lib/**/*', 'node_modules', 'cognito-deployment/**/*', '**/*/integration.test.ts'],
    hookTimeout: 60000
  }
});
