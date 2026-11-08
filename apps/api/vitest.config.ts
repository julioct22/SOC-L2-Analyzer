import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['test/**/*.test.ts'],
    // Las pruebas del motor no necesitan BD; se definen variables mínimas para que config/env no falle si se importa
    env: {
      DATABASE_URL: 'postgres://test:test@localhost:5432/test',
      JWT_SECRET: 'test-secret-test-secret-test-secret-123',
      ADMIN_PASSWORD: 'Test#12345678',
    },
  },
});
