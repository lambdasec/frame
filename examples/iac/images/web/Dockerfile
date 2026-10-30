FROM node:22.11-bookworm AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx
ADD https://download.example.com/geoip/GeoLite2-Country.tar.gz /usr/share/geoip/
COPY --from=build /src/dist /usr/share/nginx/html
