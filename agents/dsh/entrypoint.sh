#!/bin/sh
set -eu
if [ -z "${DSH_WEB_HOST:-}" ]; then
  DSH_WEB_HOST="$(node -e 'const n=require("os").networkInterfaces();for(const v of Object.values(n)){for(const a of v||[]){if(a.family==="IPv4"&&!a.internal){console.log(a.address);process.exit(0)}}}')"
fi
exec dsh web --host "$DSH_WEB_HOST" --port "${DSH_WEB_PORT:-8080}" --no-open "$@"
