#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ "$1" = "push" ]; then
    DATA_DIR="${2:?DATA_DIR is necessary}"
    message="${3:-update}"

    # Remove old encrypted dir if meta.json exists
    if [ -f meta.json ]; then
        OLD_DIR=$(python3 -c "import json; print(json.load(open('meta.json'))['root_alias'])")
        rm -rf "$OLD_DIR"
    fi

    python3 "$SCRIPT_DIR/encrypt.py" --folder "$DATA_DIR"
    ENCRYPTED_DIR=$(python3 -c "import json; print(json.load(open('meta.json'))['root_alias'])")

    git add meta.json "$ENCRYPTED_DIR" && \
    git commit -m "${message}" && \
    git push && \
    exit 0
fi

if [ "$1" = "pull" ]; then
    git pull && \
    python3 "$SCRIPT_DIR/encrypt.py" --decrypt && \
    exit 0
fi

exit 2
