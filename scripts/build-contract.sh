#!/usr/bin/env bash
# Copyright 2026 Quantova Inc
# SPDX-License-Identifier: Apache-2.0 OR MIT

set -euo pipefail

QUANTA_REPO="https://github.com/Quantova/Quanta-Smart-Contract-language.git"
QUANTA_COMMIT="ccdf4c20b167daf2b60a87267c1e12557738d354"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if [ -n "${QUANTA_DIR:-}" ]; then
  SRC="$(cd "$QUANTA_DIR" && pwd)"
  have="$(git -C "$SRC" rev-parse HEAD)"
  if [ "$have" != "$QUANTA_COMMIT" ]; then
    echo "QUANTA_DIR is at $have, the contract is built with $QUANTA_COMMIT" >&2
    exit 1
  fi
  if [ -n "$(git -C "$SRC" status --porcelain --untracked-files=no)" ]; then
    echo "QUANTA_DIR has local changes, build from a clean checkout" >&2
    exit 1
  fi
else
  SRC="$WORK/quanta"
  git init -q "$SRC"
  git -C "$SRC" fetch -q --depth 1 "$QUANTA_REPO" "$QUANTA_COMMIT"
  git -C "$SRC" checkout -q FETCH_HEAD
fi

cargo build --release --locked -p quanta-cli --manifest-path "$SRC/Cargo.toml" --target-dir "$WORK/target"
CLI="$WORK/target/release/quanta-cli"

interface() {
  node -e '
    const fs = require("fs");
    const doc = JSON.parse(fs.readFileSync(0, "utf8"));
    const container = fs.readFileSync(process.argv[1]);
    if (!doc.ok || !Array.isArray(doc.contracts) || doc.contracts.length !== 1) throw new Error("the compiler emitted no single contract");
    if (!Buffer.from(doc.contracts[0].container, "hex").equals(container)) throw new Error("the emitted container differs from the built one");
    for (const c of doc.contracts) delete c.container;
    process.stdout.write(JSON.stringify(doc, null, 2) + "\n");
  ' "$1"
}

compile() {
  local source="$1" name
  name="$(basename "$source" .qs)"
  cp "$source" "$WORK/$name.qs"
  (cd "$WORK" && env -u QUANTA_PROVENANCE_KEY_FILE "$CLI" check "$name.qs" >/dev/null)
  (cd "$WORK" && env -u QUANTA_PROVENANCE_KEY_FILE "$CLI" build "$name.qs" >/dev/null)
  (cd "$WORK" && env -u QUANTA_PROVENANCE_KEY_FILE "$CLI" emit "$name.qs") | interface "$WORK/$name.qbc" > "$WORK/$name.interface.json"
}

same() {
  if ! cmp -s "$1" "$2"; then
    echo "the rebuilt $3 differs from $2" >&2
    exit 1
  fi
}

compile "$ROOT/contract/QStamp.qs"

if command -v sha256sum >/dev/null 2>&1; then
  built="$(sha256sum "$WORK/QStamp.qbc" | cut -d ' ' -f 1)"
else
  built="$(shasum -a 256 "$WORK/QStamp.qbc" | cut -d ' ' -f 1)"
fi
expected="$(cut -d ' ' -f 1 "$ROOT/contract/QStamp.qbc.sha256")"

if [ "$built" != "$expected" ]; then
  echo "the rebuilt container hashes to $built, the repository expects $expected" >&2
  exit 1
fi
same "$WORK/QStamp.qbc" "$ROOT/contract/QStamp.qbc" "container"
same "$WORK/QStamp.interface.json" "$ROOT/contract/QStamp.interface.json" "interface"
echo "contract/QStamp.qbc and its interface rebuild byte for byte from contract/QStamp.qs with the Quanta compiler at $QUANTA_COMMIT ($built)"

if [ -n "${QSTAMP_TEMPLATES_DIR:-}" ]; then
  for name in QStampIssuer QStampCouncil; do
    compile "$QSTAMP_TEMPLATES_DIR/contracts/$name.qs"
    same "$WORK/$name.qbc" "$QSTAMP_TEMPLATES_DIR/contracts/$name.qbc" "container of $name"
    same "$WORK/$name.interface.json" "$ROOT/contract/templates/$name.interface.json" "interface of $name"
  done
  echo "the issuer and council template interfaces rebuild byte for byte from $QSTAMP_TEMPLATES_DIR"
fi
