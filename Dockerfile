FROM node:22-alpine AS builder
WORKDIR /app
RUN apk add --no-cache git
COPY package*.json ./
RUN npm ci
COPY tsconfig.json vite.config.ts ./
COPY src ./src
COPY ui ./ui
COPY scripts ./scripts
COPY plugin ./plugin
RUN npm run build

FROM node:22-alpine
WORKDIR /app
RUN apk add --no-cache git
COPY package*.json ./
RUN npm ci --omit=dev
COPY --from=builder /app/dist ./dist
COPY LICENSE COMMERCIAL_LICENSE.md README.md ./
ENTRYPOINT ["node", "dist/cli.js"]
