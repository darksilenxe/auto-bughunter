FROM golang:1.25-alpine AS build
WORKDIR /app

COPY go.mod .
RUN go mod download

COPY . .
RUN go build -o /out/server ./cmd/server

FROM alpine:latest
RUN apk add --no-cache ca-certificates chromium nss
WORKDIR /app

COPY --from=build /out/server /app/server

ENV PORT=8080
EXPOSE 8080

CMD ["/app/server"]
