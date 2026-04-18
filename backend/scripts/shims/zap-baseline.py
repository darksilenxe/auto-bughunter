#!/bin/sh
# Shim — runs zap-baseline.py inside the `zap` Docker Compose sidecar.
# The upstream zaproxy/zap-stable image already ships zap-baseline.py and all
# of its Python dependencies on its $PATH.
exec /usr/local/bin/sidecar-exec zap zap-baseline.py "$@"
