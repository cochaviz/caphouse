#!/bin/sh
# caphouse-monitor – continuous capture with bounded on-disk footprint.
#
# Wraps tcpdump's built-in file rotation with caphouse ingest: each completed
# rotation file is ingested into ClickHouse and then removed.
#
# All ring files share a single capture ID so the monitoring session appears
# as one capture in ClickHouse regardless of how many rotations occur.
#
# Dependencies: tcpdump, caphouse
#   macOS: lsof (pre-installed)
#   Linux: inotifywait (inotify-tools)

set -eu

IFACE=
DSN="${CAPHOUSE_DSN:-}"
SENSOR=
ROTATE=60
DIR=/var/capture

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
  -D DIR       Directory for rotation files (default: $DIR)
  -h           Show this help
EOF
}

while getopts 'i:d:s:t:D:h' opt; do
    case $opt in
        i) IFACE=$OPTARG ;;
        d) DSN=$OPTARG ;;
        s) SENSOR=$OPTARG ;;
        t) ROTATE=$OPTARG ;;
        D) DIR=$OPTARG ;;
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

# Start tcpdump in the background; kill it when we exit.
# -G rotates every ROTATE seconds. -C and -W are intentionally omitted: when
# either is combined with -G, tcpdump appends a numeric suffix to filenames.
# On-disk footprint is bounded naturally since each file is deleted after ingest.
tcpdump -i "$IFACE" -G "$ROTATE" -w "$DIR/ring_%Y%m%d_%H%M%S.pcap" &
TCPDUMP_PID=$!
trap 'kill "$TCPDUMP_PID" 2>/dev/null; wait "$TCPDUMP_PID" 2>/dev/null' INT TERM EXIT

ingest() {
    caphouse --silent --sensor="$SENSOR" --file="$1" --capture="$CAPTURE_ID" && rm -f "$1"
}

# On any exit: stop tcpdump, wait for it to close its current file, then ingest
# whatever remains. The guard prevents the body running twice when both an INT/TERM
# trap and the EXIT trap fire in sequence.
_cleaned=0
cleanup() {
    [ "$_cleaned" = 1 ] && return
    _cleaned=1
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
