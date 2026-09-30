#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
#
# Bring a fresh Garage to the state the engine needs, once, and do nothing the
# second time.
#
# This used to be eight commands in a comment, ending with "put the key it prints
# into .env and bring the stack up again". That is not a deployment, it is a
# recipe, and every step of it is a step someone gets wrong at two in the morning.
# Worse, it made the stack need two compose files, and a `docker compose up -d
# engine` that forgot the second one silently pointed the engine at a local path
# instead of the blob store, which DuckLake refuses — a crash loop caused by
# omitting an argument.
#
# So: everything here is idempotent, and the credentials it creates are written
# where the engine can read them instead of being printed for a human to carry.
set -eu

CORPUS_BUCKET="${CORPUS_BUCKET:-lazaret-corpus}"
CUSTODY_BUCKET="${CUSTODY_BUCKET:-lazaret-custody}"
ZONE="${GARAGE_ZONE:-dc1}"
CAPACITY="${GARAGE_CAPACITY:-100G}"
CREDS_DIR="${CREDS_DIR:-/var/lib/lazaret/blobcreds}"
KEY_NAME="lazaret"

# The engine runs unprivileged and this script runs as root, so the credential has
# to be handed over deliberately. Pinned in the engine's Dockerfile, which is why
# it can be a number here; 0 means "leave it owned by root", for anyone running the
# engine as root too.
OWNER_UID="${OWNER_UID:-10002}"
OWNER_GID="${OWNER_GID:-10002}"

say() { echo "garage-init: $*"; }

# 1. Wait for the node. depends_on only promises the container started, and
#    Garage takes a moment to open its RPC socket.
say "waiting for garage"
i=0
until garage status >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -gt 120 ]; then
    say "garage did not answer within two minutes"
    garage status || true
    exit 1
  fi
  sleep 1
done

# 2. Credentials. An operator's own take precedence; otherwise generate a pair
#    once and keep them on the shared volume, which is also where the engine
#    reads them from. Nothing is ever printed for someone to copy.
mkdir -p "$CREDS_DIR"
# Writable while this script is working; locked down at the end of the block.
chmod 0700 "$CREDS_DIR"
if [ -n "${S3_ACCESS_KEY:-}" ] && [ -n "${S3_SECRET_KEY:-}" ]; then
  say "using the credentials supplied in the environment"
  printf '%s' "$S3_ACCESS_KEY" > "$CREDS_DIR/access_key"
  printf '%s' "$S3_SECRET_KEY" > "$CREDS_DIR/secret_key"
elif [ ! -s "$CREDS_DIR/access_key" ] || [ ! -s "$CREDS_DIR/secret_key" ]; then
  # Garage's own format: GK followed by 24 hex characters.
  printf 'GK%s' "$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')" > "$CREDS_DIR/access_key"
  head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$CREDS_DIR/secret_key"
  say "generated a blob store credential"
else
  say "reusing the credential on the volume"
fi
# Owned by the engine and read-only: it reads this, and nothing else needs to.
if [ "$OWNER_UID" != "0" ]; then
  chown "$OWNER_UID:$OWNER_GID" "$CREDS_DIR" "$CREDS_DIR/access_key" "$CREDS_DIR/secret_key"
fi
chmod 0500 "$CREDS_DIR"
chmod 0400 "$CREDS_DIR/access_key" "$CREDS_DIR/secret_key"
ACCESS_KEY="$(cat "$CREDS_DIR/access_key")"
SECRET_KEY="$(cat "$CREDS_DIR/secret_key")"

# 3. Cluster layout. Until a node has a role, every write is a 503.
NODE_ID="$(garage node id -q 2>/dev/null | cut -d@ -f1)"
if [ -z "$NODE_ID" ]; then
  say "could not read the node id"
  exit 1
fi
# `layout show` prints the id truncated to sixteen characters while `node id`
# gives all sixty-four, so matching the full one never hits — and the layout was
# reassigned and reapplied on every single `up`, bumping the cluster layout
# version each time. Harmless on one node; on a real cluster that is a data
# movement nobody asked for.
SHORT_ID="$(echo "$NODE_ID" | cut -c1-16)"
if garage layout show 2>/dev/null | grep -q "$SHORT_ID"; then
  say "layout already assigned"
else
  say "assigning $NODE_ID to zone $ZONE with $CAPACITY"
  garage layout assign -z "$ZONE" -c "$CAPACITY" "$NODE_ID"
  # apply takes the version it is creating, which is whatever is current plus one.
  VERSION="$(garage layout show 2>/dev/null | sed -n 's/.*layout version: *\([0-9]*\).*/\1/p' | tail -1)"
  garage layout apply --version "$((${VERSION:-0} + 1))"
fi

# 4. Buckets. Two, never one: DuckLake rewrites and expires what it owns during
#    compaction, and a compaction must not be able to delete mail under hold.
for bucket in "$CORPUS_BUCKET" "$CUSTODY_BUCKET"; do
  if garage bucket info "$bucket" >/dev/null 2>&1; then
    say "bucket $bucket exists"
  else
    say "creating bucket $bucket"
    garage bucket create "$bucket"
  fi
done

# 5. The key, and its permissions. Importing is what lets the credential be
#    decided here rather than read back out of Garage afterwards.
if garage key info "$ACCESS_KEY" >/dev/null 2>&1; then
  say "key $ACCESS_KEY exists"
else
  say "importing key $ACCESS_KEY"
  garage key import "$ACCESS_KEY" "$SECRET_KEY" -n "$KEY_NAME" --yes
fi
for bucket in "$CORPUS_BUCKET" "$CUSTODY_BUCKET"; do
  garage bucket allow --read --write "$bucket" --key "$ACCESS_KEY" >/dev/null
done

say "ready: $CORPUS_BUCKET and $CUSTODY_BUCKET, key $ACCESS_KEY"
