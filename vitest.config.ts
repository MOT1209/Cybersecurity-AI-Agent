import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['test/**/*.test.ts'],
    // Runs before every test file: strips AI credentials so no test can reach
    // a live model, and pins the sandbox to simulation.
    setupFiles: ['test/setup.ts'],
    env: {
      NODE_ENV: 'test',
    },
  },
});
