# One-shot container that generates a self-signed certificate covering
# every backend → sidecar HTTP endpoint in the compose stack. The cert is
# written to a shared volume mounted read-only into each sidecar (for
# `uvicorn --ssl-keyfile/--ssl-certfile`) and into the backend container
# (as the CA bundle it trusts when calling sidecar URLs over https://).
#
# The cert is generated once and re-used on every restart — the entrypoint
# is idempotent so `docker compose up` doesn't churn keys.
FROM alpine:3.20

RUN apk add --no-cache openssl

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
