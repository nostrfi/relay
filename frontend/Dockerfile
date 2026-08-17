# syntax=docker/dockerfile:1

# ---- Builder ----
FROM node:22-bookworm-slim AS builder

RUN corepack enable

WORKDIR /build

# Cache deps first
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile

# Copy source and build the Nuxt SSR (node-server preset) output
COPY . .
RUN pnpm build

# ---- Runtime ----
FROM node:22-bookworm-slim

WORKDIR /app

# Nitro's node-server preset output is self-contained (bundled deps) —
# no separate `pnpm install --prod` needed in the runtime image.
COPY --from=builder /build/.output /app/.output

ENV PORT=3000
ENV HOST=0.0.0.0
EXPOSE 3000

ENTRYPOINT ["node", "/app/.output/server/index.mjs"]
