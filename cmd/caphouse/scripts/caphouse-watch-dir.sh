#!/bin/sh
# caphouse-watch – ingest PCAP files dropped into a watched directory.
#
# Watches DIR for new PCAP files (*.pcap, *.pcapng). When a file finishes
# writing it is ingested into ClickHouse and removed from disk on success.
#
# Useful as a "drop folder": configure any tool to write PCAPs into DIR, and
# caphouse-watch will continuously drain and ingest them.
#
# If a ClickHouse ingest fails (e.g. network outage), the file is kept on disk.
# A background retry loop re-attempts failed files every RETRY seconds so no
# data is permanently lost due to transient connectivity issues.
#
# Dependencies: caphouse
#   Linux: inotifywait (inotify-tools)
#   macOS: lsof (pre-installed)

set -eu

DSN="${CAPHOUSE_DSN:-}"
SENSOR=
DIR=
RETRY=60

usage() {
    cat <<EOF
Usage: caphouse-watch -D DIR [OPTIONS]

Watch DIR for PCAP files (*.pcap, *.pcapng), ingest each into ClickHouse,
and remove it from disk on success.

Options:
  -D DIR       Directory to watch (required)
  -d DSN       ClickHouse DSN (default: \$CAPHOUSE_DSN)
  -s SENSOR    Sensor name (defaults to system hostname)
  -r SECS      Interval between retry scans for failed ingests (default: $RETRY)
  -h           Show this help
EOF
}

while getopts 'D:d:s:r:h' opt; do
    case $opt in
        D) DIR=$OPTARG ;;
        d) DSN=$OPTARG ;;
        s) SENSOR=$OPTARG ;;
        r) RETRY=$OPTARG ;;
        h) usage; exit 0 ;;
        *) usage >&2; exit 1 ;;
    esac
done

[ -n "$DIR" ] || { echo "caphouse-watch: -D DIR is required" >&2; exit 1; }
[ -n "$DSN"  ] || { echo "caphouse-watch: DSN is required (-d or CAPHOUSE_DSN)" >&2; exit 1; }

export CAPHOUSE_DSN="$DSN"

mkdir -p "$DIR"

is_pcap() {
    case "$1" in
        *.pcap|*.pcapng) return 0 ;;
        *) return 1 ;;
    esac
}

ingest() {
    f="$1"
    is_pcap "$f" || return 0
    [ -f "$f" ]  || return 0
    if [ -n "$SENSOR" ]; then
        caphouse --silent --sensor="$SENSOR" "$f" && rm -f "$f"
    else
        caphouse --silent "$f" && rm -f "$f"
    fi
}

# Drain any files already present when the watcher starts.
for f in "$DIR"/*.pcap "$DIR"/*.pcapng; do
    [ -f "$f" ] && ingest "$f"
done

# Background loop: retry files that failed to ingest (network outage recovery).
# On Linux the inotifywait loop only fires on close_write and won't re-fire for
# files whose ingest failed. This loop fills that gap by periodically rescanning.
retry_failed() {
    while true; do
        sleep "$RETRY"
        for f in "$DIR"/*.pcap "$DIR"/*.pcapng; do
            [ -f "$f" ] && ingest "$f"
        done
    done
}
retry_failed &
RETRY_PID=$!
trap 'kill "$RETRY_PID" 2>/dev/null || true' EXIT INT TERM

case "$(uname)" in
    Darwin)
        # Poll the directory and skip files still held open by a writer.
        while true; do
            for f in "$DIR"/*.pcap "$DIR"/*.pcapng; do
                [ -f "$f" ] || continue
                lsof -- "$f" >/dev/null 2>&1 && continue
                ingest "$f"
            done
            sleep 2
        done
        ;;
    *)
        # close_write fires only after the writing process closes the file.
        inotifywait -m -e close_write --format '%w%f' "$DIR" | while read -r FILE; do
            ingest "$FILE"
        done
        ;;
esac
