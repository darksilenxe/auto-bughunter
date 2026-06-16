FROM node:20-alpine AS build
WORKDIR /app

ARG VITE_API_BASE=http://localhost:8080
ENV VITE_API_BASE=${VITE_API_BASE}

ARG VITE_API_KEY=
ENV VITE_API_KEY=${VITE_API_KEY}

ARG VITE_WORKSPACE_ID=default
ENV VITE_WORKSPACE_ID=${VITE_WORKSPACE_ID}

COPY package.json ./
RUN npm install && npm install @rolldown/binding-linux-x64-musl

COPY . .
RUN npm run build

FROM nginx:1.30.0-alpine
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
