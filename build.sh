#!/usr/bin/env bash
# Build curated Pi-hole domain lists from sources.txt.
set -euo pipefail
cd "$(dirname "$0")"
exec python3 build.py "$@"
