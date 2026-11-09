FROM node:24-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY snippets/ /etc/nginx/snippets/
COPY --chmod=755 configure-tls.sh /docker-entrypoint.d/40-configure-tls.sh
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80 443
