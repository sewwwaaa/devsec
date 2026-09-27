# Frontend Web Server Container (Nginx Alpine Hardened)
FROM nginx:1.27-alpine

# Apply latest security patches to base OS
RUN apk update && apk upgrade --no-cache

# Remove default nginx static assets
RUN rm -rf /usr/share/nginx/html/*

# Copy custom reverse-proxy and security configuration
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf

# Copy static assets (HTML, CSS, JS)
COPY frontend/index.html /usr/share/nginx/html/index.html
COPY frontend/styles.css /usr/share/nginx/html/styles.css
COPY frontend/app.js /usr/share/nginx/html/app.js

# Healthcheck for container orchestration
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD wget --quiet --tries=1 --spider http://localhost/ || exit 1

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
