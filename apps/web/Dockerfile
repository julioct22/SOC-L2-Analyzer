# ---------- 1) Build de la SPA con Vite ----------
FROM node:22-bookworm-slim AS build
WORKDIR /app
COPY package.json yarn.lock ./
COPY apps/api/package.json apps/api/
COPY apps/web/package.json apps/web/
COPY packages/shared/package.json packages/shared/
RUN yarn install --frozen-lockfile --network-timeout 600000
COPY tsconfig.base.json ./
COPY packages/shared packages/shared
COPY apps/web apps/web
RUN yarn workspace @soc/web build

# ---------- 2) Servidor estático + proxy /api ----------
FROM nginx:1.27-alpine
COPY apps/web/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/apps/web/dist /usr/share/nginx/html
EXPOSE 80
