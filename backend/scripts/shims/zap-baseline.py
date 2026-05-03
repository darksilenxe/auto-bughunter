#!/bin/sh
# Shim — runs zap-baseline.py inside the `zap` Docker Compose sidecar.
#
# NOTE: This file is a POSIX shell script despite its `.py` extension. The
# extension is intentional and MUST be preserved: the Go scanner looks the
# tool up with exec.LookPath("zap-baseline.py") (default value of the
# ZAP_BASELINE_BINARY env var), so the file on $PATH has to match that name
# byte-for-byte. The upstream zaproxy/zap-stable image already ships
# zap-baseline.py and all of its Python dependencies on its own $PATH.
exec /usr/local/bin/sidecar-exec zap zap-baseline.py "$@"

