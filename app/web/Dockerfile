FROM node:22-bookworm-slim
WORKDIR /app
COPY package.json package-lock.json ./
# --include=dev so vite (a devDependency) is present even when Railway builds
# with NODE_ENV=production — the `ui` service runs the vite dev server.
RUN npm ci --include=dev
COPY . .
EXPOSE 5173
# Vite binds 0.0.0.0 (server.host) and proxies /api to $API_PROXY.
CMD ["npm", "run", "dev"]
