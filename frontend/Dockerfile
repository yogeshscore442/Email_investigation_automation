# ==============================================================================
# PhishScope SOC - Frontend Production Multi-Stage Dockerfile
# Stage 1: Vite React compilation | Stage 2: Nginx unprivileged serving
# ==============================================================================
FROM node:20-alpine AS builder

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

# Stage 2: Nginx Web Server
FROM nginx:alpine

# Remove default static pages
RUN rm -rf /usr/share/nginx/html/*

# Copy compiled frontend SPA
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy hardened nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:80/ || exit 1

CMD ["nginx", "-g", "daemon off;"]

