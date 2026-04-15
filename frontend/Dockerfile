FROM node:20-alpine AS build
WORKDIR /app

ARG VITE_API_BASE=http://localhost:8080
ENV VITE_API_BASE=${VITE_API_BASE}

COPY package.json ./
RUN npm install

COPY . .
RUN npm run build

FROM nginx:1.29.8-alpine
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
