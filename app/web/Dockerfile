FROM node:22-bookworm-slim
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
EXPOSE 5173
# Vite binds 0.0.0.0 (server.host) and proxies /api to $API_PROXY.
CMD ["npm", "run", "dev"]
