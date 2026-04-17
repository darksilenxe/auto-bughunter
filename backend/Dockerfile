FROM golang:1.25-alpine AS build
WORKDIR /app

COPY go.mod .
RUN go mod download

COPY . .
RUN go build -o /out/server ./cmd/server

# Build the nuclei binary from source so it matches the target architecture.
ARG NUCLEI_VERSION=v3.7.1
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION}

# ---------------------------------------------------------------------------
# Download and unpack OWASP ZAP (provides zap-baseline.py).
# ---------------------------------------------------------------------------
FROM alpine:latest AS zap-download
ARG ZAP_VERSION=2.15.0
RUN apk add --no-cache wget \
    && wget -q "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz" \
    && tar -xzf "ZAP_${ZAP_VERSION}_Linux.tar.gz" \
    && mv "ZAP_${ZAP_VERSION}" /opt/zaproxy \
    && rm "ZAP_${ZAP_VERSION}_Linux.tar.gz"

# ---------------------------------------------------------------------------
# Runtime image
# ---------------------------------------------------------------------------
FROM alpine:latest
RUN apk add --no-cache \
    ca-certificates \
    chromium \
    nss \
    openjdk17-jre-headless \
    python3

WORKDIR /app

COPY --from=build /out/server /app/server
COPY --from=build /go/bin/nuclei /usr/local/bin/nuclei
COPY --from=zap-download /opt/zaproxy /opt/zaproxy

# Expose zap-baseline.py on PATH and ensure it is executable.
RUN chmod +x /opt/zaproxy/zap-baseline.py \
    && ln -s /opt/zaproxy/zap-baseline.py /usr/local/bin/zap-baseline.py

ENV PORT=8080
EXPOSE 8080

CMD ["/app/server"]
