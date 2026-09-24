# Multi-stage web frontend build: node build -> nginx (unprivileged, non-root).
# Build-time API base URL: docker build --build-arg VITE_API_BASE_URL=https://api.example.com .
FROM node:22-alpine AS build

WORKDIR /src
ARG VITE_API_BASE_URL=""
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL

COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY . ./
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.27-alpine

# SPA fallback config (history API routing): serve index.html for unknown paths.
RUN printf 'server {\n  listen 8080;\n  root /usr/share/nginx/html;\n  index index.html;\n  location / {\n    try_files $uri $uri/ /index.html;\n  }\n  location /healthz {\n    access_log off;\n    return 200 "ok";\n    add_header Content-Type text/plain;\n  }\n}\n' > /etc/nginx/conf.d/default.conf

COPY --from=build /src/dist /usr/share/nginx/html
USER nginx
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1
CMD ["nginx", "-g", "daemon off;"]
