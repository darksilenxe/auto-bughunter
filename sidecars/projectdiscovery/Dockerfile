# ---------------------------------------------------------------------------
# Shared ProjectDiscovery sidecar
#
# A single container that exposes every ProjectDiscovery CLI the backend
# scanner shells out to (subfinder, httpx, cloudlist, naabu, dnsx, shuffledns,
# katana, tlsx, cdncheck, asnmap, vulnx). Each tool is copied directly out of its official
# upstream image so we benefit from upstream's pinned dependencies and stay
# off Go module rebuilds in this repo.
#
# The matching shims under backend/scripts/shims/<tool> resolve to
# `docker compose exec -T projectdiscovery <tool> ...`, which means the Go
# scanner's existing exec.LookPath / exec.CommandContext code keeps working
# unchanged.
#
# Pinning rationale: pin to a known-good minor for each tool. Bump the tags
# in this single file to upgrade the whole suite.
# ---------------------------------------------------------------------------

FROM projectdiscovery/subfinder:v2.13.0   AS subfinder
FROM projectdiscovery/httpx:v1.9.0        AS httpx
FROM projectdiscovery/cloudlist:v1.4.0    AS cloudlist
FROM projectdiscovery/naabu:v2.5.0        AS naabu
FROM projectdiscovery/dnsx:v1.2.2         AS dnsx
FROM projectdiscovery/shuffledns:v1.0.8   AS shuffledns
FROM projectdiscovery/katana:v1.5.0       AS katana
FROM projectdiscovery/tlsx:v1.2.2         AS tlsx
FROM projectdiscovery/cdncheck:v1.1.36    AS cdncheck
FROM projectdiscovery/asnmap:v1.1.1       AS asnmap
FROM projectdiscovery/vulnx:v1.0.0        AS vulnx

FROM alpine:3.20

RUN apk add --no-cache ca-certificates libc6-compat

COPY --from=subfinder  /usr/local/bin/subfinder  /usr/local/bin/subfinder
COPY --from=httpx      /usr/local/bin/httpx      /usr/local/bin/httpx
COPY --from=cloudlist  /usr/local/bin/cloudlist  /usr/local/bin/cloudlist
COPY --from=naabu      /usr/local/bin/naabu      /usr/local/bin/naabu
COPY --from=dnsx       /usr/local/bin/dnsx       /usr/local/bin/dnsx
COPY --from=shuffledns /usr/bin/shuffledns       /usr/local/bin/shuffledns
COPY --from=katana     /usr/local/bin/katana     /usr/local/bin/katana
COPY --from=tlsx       /usr/local/bin/tlsx       /usr/local/bin/tlsx
COPY --from=cdncheck   /usr/local/bin/cdncheck   /usr/local/bin/cdncheck
COPY --from=asnmap     /usr/local/bin/asnmap     /usr/local/bin/asnmap
COPY --from=vulnx      /usr/local/bin/vulnx      /usr/local/bin/vulnx

# Keep the container alive so `docker compose exec` works on demand. Each
# invocation is a short-lived child of this PID 1.
ENTRYPOINT ["/bin/sh", "-c", "tail -f /dev/null"]
