#!/bin/sh
# caphouse-monitor – continuous capture with bounded on-disk footprint.
#
# Wraps tcpdump's built-in file rotation with caphouse ingest: each completed
# rotation file is ingested into ClickHouse and then removed.
#
# All ring files share a single capture ID so the monitoring session appears
# as one capture in ClickHouse regardless of how many rotations occur.
#
# If a ClickHouse ingest fails (e.g. network outage), the rotation file is kept
# on disk. A background retry loop re-attempts failed files every RETRY seconds
# so no data is permanently lost due to transient connectivity issues.
#
# Dependencies: tcpdump, caphouse
#   macOS: lsof (pre-installed)
#   Linux: inotifywait (inotify-tools)

set -eu

IFACE=
DSN="${CAPHOUSE_DSN:-}"
SENSOR=
ROTATE=60
RETRY=60
DIR=/var/capture
FILTER=

usage() {
    cat <<EOF
Usage: caphouse-monitor -i IFACE [OPTIONS]

Continuously capture on IFACE using tcpdump rotation, ingesting each
completed file into ClickHouse and removing it on success.

Options:
  -i IFACE     Network interface to capture on (required)
  -d DSN       ClickHouse DSN (default: \$CAPHOUSE_DSN)
  -s SENSOR    Sensor name (required)
  -t SECS      Rotate after SECS seconds (default: $ROTATE)
  -r SECS      Interval between retry scans for failed ingests (default: $RETRY)
  -D DIR       Directory for rotation files (default: $DIR)
  -f FILTER    tcpdump filter expression (e.g. "host 1.2.3.4 and port 80")
  -h           Show this help
EOF
}

while getopts 'i:d:s:t:r:D:f:h' opt; do
    case $opt in
        i) IFACE=$OPTARG ;;
        d) DSN=$OPTARG ;;
        s) SENSOR=$OPTARG ;;
        t) ROTATE=$OPTARG ;;
        r) RETRY=$OPTARG ;;
        D) DIR=$OPTARG ;;
        f) FILTER=$OPTARG ;;
        h) usage; exit 0 ;;
        *) usage >&2; exit 1 ;;
    esac
done

[ -n "$IFACE"  ] || { echo "caphouse-monitor: -i IFACE is required" >&2; exit 1; }
[ -n "$DSN"    ] || { echo "caphouse-monitor: DSN is required (-d or CAPHOUSE_DSN)" >&2; exit 1; }
[ -n "$SENSOR" ] || { echo "caphouse-monitor: sensor is required (-s)" >&2; exit 1; }

mkdir -p "$DIR"

# Export DSN so caphouse picks it up from the environment.
export CAPHOUSE_DSN="$DSN"

# One stable capture ID for the whole monitoring session; all ring files are
# ingested into this single capture in ClickHouse.
CAPTURE_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')

# Check whether FILE is currently held open by PID.
# On Linux we inspect /proc/$pid/fd; on other systems we fall back to lsof.
file_open_by() {
    _file="$1" _pid="$2"
    if [ -d "/proc/$_pid/fd" ]; then
        for _fd in /proc/"$_pid"/fd/*; do
            [ "$(readlink "$_fd" 2>/dev/null)" = "$_file" ] && return 0
        done
        return 1
    else
        lsof -a -p "$_pid" -- "$_file" >/dev/null 2>&1
    fi
}

ingest() {
    caphouse --silent --sensor="$SENSOR" --capture="$CAPTURE_ID" "$1" && rm -f "$1"
}

# Start tcpdump in the background; kill it when we exit.
# -G rotates every ROTATE seconds. -C and -W are intentionally omitted: when
# either is combined with -G, tcpdump appends a numeric suffix to filenames.
# On-disk footprint is bounded naturally since each file is deleted after ingest.
# shellcheck disable=SC2086
tcpdump -i "$IFACE" -G "$ROTATE" -w "$DIR/ring_%Y%m%d_%H%M%S.pcap" $FILTER &
TCPDUMP_PID=$!

# Background loop: retry files that failed to ingest (network outage recovery).
# On Linux the inotifywait loop only fires on close_write and won't re-fire for
# files whose ingest failed. This loop fills that gap by periodically rescanning.
retry_failed() {
    while kill -0 "$TCPDUMP_PID" 2>/dev/null; do
        sleep "$RETRY"
        for f in "$DIR"/ring_*.pcap; do
            [ -f "$f" ] || continue
            # Skip the file tcpdump currently has open.
            file_open_by "$f" "$TCPDUMP_PID" && continue
            ingest "$f"
        done
    done
}
retry_failed &
RETRY_PID=$!

# On any exit: stop background processes, wait for tcpdump to close its current
# file, then ingest whatever remains. The _cleaned guard prevents the body
# running twice when both an INT/TERM trap and the EXIT trap fire in sequence.
_cleaned=0
cleanup() {
    [ "$_cleaned" = 1 ] && return
    _cleaned=1
    kill "$RETRY_PID" 2>/dev/null || true
    kill "$TCPDUMP_PID" 2>/dev/null
    wait "$TCPDUMP_PID" 2>/dev/null
    for f in "$DIR"/ring_*.pcap; do
        [ -f "$f" ] && ingest "$f"
    done
}
trap cleanup INT TERM EXIT

case "$(uname)" in
    Darwin)
        # fswatch fires on file creation, before tcpdump has finished writing.
        # Instead, poll the directory and skip files tcpdump still has open.
        # lsof -a ANDs the selectors: without -a, lsof ORs -p and the filename,
        # which always succeeds because tcpdump has some file open.
        while kill -0 "$TCPDUMP_PID" 2>/dev/null; do
            for f in "$DIR"/ring_*.pcap; do
                [ -f "$f" ] || continue
                lsof -a -p "$TCPDUMP_PID" -- "$f" >/dev/null 2>&1 && continue
                ingest "$f"
            done
            sleep 2
        done
        ;;
    *)
        # close_write fires only after tcpdump has closed the completed file.
        inotifywait -m -e close_write --format '%w%f' "$DIR" | while read -r FILE; do
            ingest "$FILE"
        done
        ;;
esac
