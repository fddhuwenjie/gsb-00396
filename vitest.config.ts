import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';

// Vitest runs the parser tests against the same TypeScript sources the browser
// app imports. No native `.ts` execution, custom loader, or specific working
// directory is required: Vitest transpiles on the fly and resolves the `@/`
// alias the same way the Vite build does.
export default defineConfig({
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  test: {
    environment: 'node',
    include: ['test/**/*.test.ts'],
    globals: false,
  },
});
