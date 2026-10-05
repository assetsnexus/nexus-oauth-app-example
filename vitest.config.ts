import { defineConfig } from 'vitest/config';
import path from 'node:path';

const modules = path.resolve(__dirname, '../../anx-npm-modules/packages');

export default defineConfig({
  resolve: {
    alias: {
      '@nexus/commands-client/testing': path.join(modules, 'commands-client/src/testing/index.ts'),
      '@nexus/commands-client': path.join(modules, 'commands-client/src/index.ts'),
      '@nexus/webhooks': path.join(modules, 'webhooks/src/index.ts'),
    },
  },
  test: { include: ['src/**/*.spec.ts'] },
});
