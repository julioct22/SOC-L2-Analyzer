import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm'],
  target: 'node22',
  platform: 'node',
  outDir: 'dist',
  clean: true,
  sourcemap: true,
  // @soc/shared es código TypeScript del monorepo: se empaqueta dentro del bundle.
  // El resto de dependencias se resuelve desde node_modules en tiempo de ejecución.
  noExternal: ['@soc/shared'],
});
