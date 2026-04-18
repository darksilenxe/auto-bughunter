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
ARG ZAP_VERSION=2.17.0
ARG ZAP_SHA256=efe799aaa3627db683b43f00c9c210aea0b75c00cc8f0a0f0434d12bb3ddde5a
RUN apk add --no-cache ca-certificates wget \
    && wget --tries=5 --timeout=60 --waitretry=10 --retry-connrefused -S \
        "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz" \
    && echo "${ZAP_SHA256}  ZAP_${ZAP_VERSION}_Linux.tar.gz" | sha256sum -c - \
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
