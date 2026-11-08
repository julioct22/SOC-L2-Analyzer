# ---------- 1) Dependencias (todas, para compilar) ----------
FROM node:22-bookworm-slim AS deps
WORKDIR /app
COPY package.json yarn.lock ./
COPY apps/api/package.json apps/api/
COPY apps/web/package.json apps/web/
COPY packages/shared/package.json packages/shared/
RUN yarn install --frozen-lockfile --network-timeout 600000

# ---------- 2) Compilación (tsup empaqueta src + @soc/shared) ----------
FROM deps AS build
COPY tsconfig.base.json ./
COPY packages/shared packages/shared
COPY apps/api apps/api
RUN yarn workspace @soc/api build

# ---------- 3) Imagen final de ejecución ----------
FROM node:22-bookworm-slim AS runtime
# Chromium headless para generar el PDF + fuentes con soporte de acentos
RUN apt-get update \
 && apt-get install -y --no-install-recommends chromium fonts-dejavu-core fonts-liberation ca-certificates \
 && rm -rf /var/lib/apt/lists/*
ENV NODE_ENV=production \
    CHROMIUM_PATH=/usr/bin/chromium
WORKDIR /app
COPY package.json yarn.lock ./
COPY apps/api/package.json apps/api/
COPY apps/web/package.json apps/web/
COPY packages/shared/package.json packages/shared/
# Solo dependencias de producción (las de la web son devDependencies, no se instalan aquí)
RUN yarn install --frozen-lockfile --production --network-timeout 600000 && yarn cache clean
COPY --from=build /app/apps/api/dist apps/api/dist
COPY apps/api/drizzle apps/api/drizzle
WORKDIR /app/apps/api
RUN mkdir -p /data && chown -R node:node /data
USER node
EXPOSE 3000
CMD ["node", "dist/index.js"]
