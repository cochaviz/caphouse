#!/usr/bin/env bash
# test_migration_compat.sh — cross-version migration compatibility test
#
# Verifies that upgrading a database initialised by the oldest supported
# caphouse binary to the current version produces bit-for-bit identical
# PCAP exports.
#
# Steps:
#   1. Build the old CLI binary at OLDEST_COMMIT via a git worktree
#   2. Build the new CLI binary from the current working tree
#   3. Use the old binary to ingest testdata into a fresh ClickHouse DB
#   4. Export: old_export.pcap
#   5. Use the new binary to ingest the same testdata (triggers runMigrations)
#   6. OPTIMIZE the packets table to force ReplacingMergeTree deduplication
#   7. Export: new_export.pcap
#   8. cmp old_export.pcap new_export.pcap — any difference is a failure
#
# Usage:
#   ./scripts/test_migration_compat.sh [--dsn DSN]
#
#   Without --dsn: starts a temporary ClickHouse Docker container.
#   With    --dsn: uses the supplied DSN (skips Docker; HTTP OPTIMIZE curl
#                  attempts to derive HTTP port from the DSN native port).
#
# Requirements: bash, git, go, docker (unless --dsn is supplied), curl, python3

set -euo pipefail

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# The last git commit before the migration system was introduced.
# Update this when a new minimum supported version is established.
readonly OLDEST_COMMIT="2267799025d70ecca28214191f133b5f468ddde9"

readonly DB_PREFIX="caphouse_compat"
readonly FROM_TIME="1970-01-01T00:00:00Z"
readonly TO_TIME="2100-01-01T00:00:00Z"
readonly SENSOR="compat-test"
readonly CH_IMAGE="clickhouse/clickhouse-server:25.3"
readonly CH_USER="default"
readonly CH_PASS="default"

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

EXTERNAL_DSN=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dsn)
            EXTERNAL_DSN="$2"
            shift 2
            ;;
        -h|--help)
            sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            echo "Usage: $0 [--dsn DSN]" >&2
            exit 1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

info()  { echo "--- $*"; }
fail()  { echo "FAIL: $*" >&2; exit 1; }

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "'$1' is required but not found in PATH"
}

free_port() {
    python3 -c "
import socket
s = socket.socket()
s.bind(('', 0))
print(s.getsockname()[1])
s.close()
"
}

wait_for_clickhouse() {
    local http_port="$1"
    local max=60
    local i=0
    info "Waiting for ClickHouse on HTTP port ${http_port}..."
    until curl -sf \
        "http://localhost:${http_port}/?user=${CH_USER}&password=${CH_PASS}&query=SELECT+1" \
        >/dev/null 2>&1
    do
        i=$(( i + 1 ))
        [[ $i -ge $max ]] && fail "ClickHouse did not become ready after ${max}s"
        sleep 1
    done
    info "ClickHouse ready (${i}s)."
}

# Derive the ClickHouse HTTP URL from a native-protocol DSN.
# clickhouse://user:pass@host:9000/db  →  http://host:8123
# Falls back to empty string if the port cannot be determined.
http_url_from_dsn() {
    local dsn="$1"
    # Extract host:port portion
    local hostport
    hostport=$(echo "$dsn" | sed -E 's|clickhouse://[^@]+@([^/]+)/.*|\1|')
    local host port
    host="${hostport%:*}"
    port="${hostport##*:}"
    # Convert native port to HTTP port (standard offset is 9000→8123; non-standard: skip)
    local http_port
    if [[ "$port" == "9000" ]]; then
        http_port="8123"
    else
        echo ""
        return
    fi
    echo "http://${host}:${http_port}"
}

# Run a SQL statement via the ClickHouse HTTP interface.
# The query is sent as the raw POST body; ClickHouse reads it directly.
ch_query() {
    curl -sf \
        "${CH_HTTP_BASE}/?user=${CH_USER}&password=${CH_PASS}" \
        --data-binary "$1" \
        >/dev/null
}

optimize_packets() {
    local db="$1"
    if [[ -z "$CH_HTTP_BASE" ]]; then
        info "HTTP URL unknown — skipping OPTIMIZE (ensure ClickHouse has merged before this runs)"
        return
    fi
    info "Optimizing tables (force ReplacingMergeTree deduplication)..."
    ch_query "OPTIMIZE TABLE ${db}.pcap_packets  FINAL" \
        || info "OPTIMIZE pcap_packets failed — continuing"
    ch_query "OPTIMIZE TABLE ${db}.pcap_captures FINAL" || true
}

cmp_files() {
    local label="$1" a="$2" b="$3"
    if cmp -s "$a" "$b"; then
        echo "  PASS: ${label}"
        return 0
    else
        echo "  FAIL: ${label}" >&2
        ls -lh "$a" "$b" >&2
        if command -v xxd >/dev/null 2>&1; then
            diff <(xxd "$a") <(xxd "$b") | head -40 >&2 || true
        fi
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

require_cmd git
require_cmd go
require_cmd curl
require_cmd python3

REPO_ROOT="$(git rev-parse --show-toplevel)"
TESTDATA_DIR="${REPO_ROOT}/testdata"
mapfile -t TESTDATA_FILES < <(find "$TESTDATA_DIR" -maxdepth 1 -name '*.pcap' | sort)
[[ ${#TESTDATA_FILES[@]} -gt 0 ]] || fail "no *.pcap files found in ${TESTDATA_DIR}"
info "Found ${#TESTDATA_FILES[@]} testdata file(s): ${TESTDATA_FILES[*]}"

WORKDIR="$(mktemp -d -t caphouse_compat_XXXXXX)"
CONTAINER_ID=""
CH_HTTP_BASE=""

cleanup() {
    local code=$?
    info "Cleaning up..."
    git worktree remove --force "${WORKDIR}/worktree" 2>/dev/null || true
    [[ -n "$CONTAINER_ID" ]] && docker stop "$CONTAINER_ID" 2>/dev/null || true
    rm -rf "$WORKDIR"
    exit "$code"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Start ClickHouse (unless DSN supplied externally)
# ---------------------------------------------------------------------------

BASE_DSN="$EXTERNAL_DSN"

if [[ -z "$BASE_DSN" ]]; then
    require_cmd docker

    CH_NATIVE_PORT="$(free_port)"
    CH_HTTP_PORT="$(free_port)"
    # Ensure the two ports differ (extremely unlikely but guard anyway)
    while [[ "$CH_HTTP_PORT" == "$CH_NATIVE_PORT" ]]; do
        CH_HTTP_PORT="$(free_port)"
    done

    info "Starting ClickHouse container (native :${CH_NATIVE_PORT}, HTTP :${CH_HTTP_PORT})..."
    CONTAINER_ID="$(docker run -d --rm \
        -e "CLICKHOUSE_USER=${CH_USER}" \
        -e "CLICKHOUSE_PASSWORD=${CH_PASS}" \
        -e CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1 \
        -p "${CH_NATIVE_PORT}:9000" \
        -p "${CH_HTTP_PORT}:8123" \
        "${CH_IMAGE}")"

    BASE_DSN="clickhouse://${CH_USER}:${CH_PASS}@localhost:${CH_NATIVE_PORT}"
    CH_HTTP_BASE="http://localhost:${CH_HTTP_PORT}"

    wait_for_clickhouse "$CH_HTTP_PORT"
else
    # Strip any trailing database component from the external DSN.
    BASE_DSN="$(echo "$BASE_DSN" | sed -E 's|/[^/]*$||')"
    CH_HTTP_BASE="$(http_url_from_dsn "${BASE_DSN}/placeholder")"
    info "Using external ClickHouse: ${BASE_DSN}"
fi

# ---------------------------------------------------------------------------
# Build binaries
# ---------------------------------------------------------------------------

OLD_BIN="${WORKDIR}/caphouse_old"
NEW_BIN="${WORKDIR}/caphouse_new"
WORKTREE="${WORKDIR}/worktree"

info "Creating git worktree at ${OLDEST_COMMIT}..."
git worktree add --detach "$WORKTREE" "$OLDEST_COMMIT"

info "Building old binary (${OLDEST_COMMIT})..."
(cd "$WORKTREE" && go build -o "$OLD_BIN" ./cmd/caphouse)

info "Building new binary (working tree)..."
(cd "$REPO_ROOT" && go build -o "$NEW_BIN" ./cmd/caphouse)

# ---------------------------------------------------------------------------
# Per-file test loop
# ---------------------------------------------------------------------------

FAILURES=0

for PCAP in "${TESTDATA_FILES[@]}"; do
    NAME="$(basename "$PCAP")"
    # Derive a safe ClickHouse identifier from the filename (replace non-alnum with _).
    DB_NAME="${DB_PREFIX}_$(echo "${NAME%.pcap}" | tr -cs 'a-zA-Z0-9' '_')"
    DSN="${BASE_DSN}/${DB_NAME}"
    info "Testing ${NAME} (db: ${DB_NAME})..."

    OLD_EXPORT="${WORKDIR}/old_${NAME}"
    NEW_EXPORT="${WORKDIR}/new_${NAME}"

    # Fresh DB per file — pre-create via HTTP so the binary can connect.
    ch_query "CREATE DATABASE IF NOT EXISTS ${DB_NAME}"

    # Phase 1: old binary initialises schema at OLDEST_COMMIT, ingests file.
    "$OLD_BIN" -s --dsn="$DSN" --sensor="$SENSOR" "$PCAP"
    "$OLD_BIN" -s -w \
        --dsn="$DSN" --capture=all \
        --from="$FROM_TIME" --to="$TO_TIME" \
        "$OLD_EXPORT"

    # Phase 2: new binary runs migrations, then re-ingests (idempotent).
    "$NEW_BIN" -s --dsn="$DSN" --sensor="$SENSOR" "$PCAP"
    optimize_packets "$DB_NAME"
    "$NEW_BIN" -s -w \
        --dsn="$DSN" --capture=all \
        --from="$FROM_TIME" --to="$TO_TIME" \
        "$NEW_EXPORT"

    # All three must be identical.
    ok=true
    cmp_files "${NAME}: original == old_export"    "$PCAP"       "$OLD_EXPORT" || ok=false
    cmp_files "${NAME}: original == new_export"    "$PCAP"       "$NEW_EXPORT" || ok=false
    cmp_files "${NAME}: old_export == new_export"  "$OLD_EXPORT" "$NEW_EXPORT" || ok=false
    $ok || FAILURES=$(( FAILURES + 1 ))
done

# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------

if [[ $FAILURES -eq 0 ]]; then
    echo "PASS: all ${#TESTDATA_FILES[@]} file(s) passed."
else
    echo "FAIL: ${FAILURES} of ${#TESTDATA_FILES[@]} file(s) failed." >&2
    exit 1
fi
