FROM golang:1.24-alpine AS build
WORKDIR /app

COPY go.mod .
RUN go mod download

COPY . .
RUN go build -o /out/server ./cmd/server

FROM alpine:3.20
RUN apk add --no-cache ca-certificates chromium nss
WORKDIR /app

COPY --from=build /out/server /app/server

ENV PORT=8080
EXPOSE 8080

CMD ["/app/server"]
