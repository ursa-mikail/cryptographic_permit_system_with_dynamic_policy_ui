FROM node:20-alpine AS builder

WORKDIR /app

# Copy package manifest and install (cached layer)
COPY package.json ./
RUN npm install --legacy-peer-deps

# Copy all source (invalidates cache when any source file changes)
COPY . .

# Run vite build directly — never goes through npm scripts or package.json
RUN ./node_modules/.bin/vite build

# ── Runtime ───────────────────────────────────────────────────────────────────
FROM nginx:1.27-alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
