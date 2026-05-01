FROM node:20-alpine AS build
WORKDIR /app

ARG VITE_API_BASE=http://localhost:8080  # nosemgrep: dockerfile.security.secret-in-build-arg.secret-in-build-arg -- VITE_API_BASE is the public URL of the backend API, not a secret
ENV VITE_API_BASE=${VITE_API_BASE}

# Note: VITE_API_KEY is intentionally NOT a build arg. Vite would inline it
# into the public JS bundle, publishing the operator's API key to every
# browser. The browser receives the key at runtime via the Settings UI
# (persisted in localStorage for that browser only).

ARG VITE_WORKSPACE_ID=default
ENV VITE_WORKSPACE_ID=${VITE_WORKSPACE_ID}

COPY package.json ./
RUN npm install

COPY . .
RUN npm run build

FROM nginx:1.30.0-alpine
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
