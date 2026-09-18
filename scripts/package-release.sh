#!/usr/bin/env bash
set -euo pipefail

[[ $# == 2 ]] || { echo '用法: package-release.sh <Linux binary> <amd64|arm64>' >&2; exit 1; }
case "$2" in amd64|arm64) ;; *) echo 'Unsupported architecture' >&2; exit 1 ;; esac
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
STAGE=$(mktemp -d)
trap 'rm -rf -- "$STAGE"' EXIT
mkdir -p "$ROOT/dist" "$STAGE/elise/example"
install -m 755 "$1" "$STAGE/elise/elise"
cp "$ROOT/scripts/elise.service" "$ROOT/scripts/elise@.service" "$ROOT/scripts/elise.openrc" "$ROOT/scripts/elise.sh" "$STAGE/elise/"
for name in elise.conf routes.toml dns.yml blockList whiteList; do
    cp "$ROOT/example/$name" "$STAGE/elise/example/$name"
done
NAME="elise-linux-$2.tar.gz"
tar -czf "$ROOT/dist/$NAME" -C "$STAGE" elise
cd "$ROOT/dist"
sha256sum "$NAME" > "$NAME.sha256"
