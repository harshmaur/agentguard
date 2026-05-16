#!/bin/bash
# bench.sh <name> <output_file> <cmd...>
# Runs <cmd...> under /usr/bin/time -v, writes stdout to <output_file>,
# emits one JSON line to stdout summarizing wall/CPU/RSS/IO/exit.
set -u

NAME="$1"
OUT="$2"
shift 2

TIMEFILE=$(mktemp)
STDERR_FILE="/tmp/audr-bench/${NAME}.stderr"

# Run under time -v; redirect stdout to OUT (may be /dev/null), stderr to file.
/usr/bin/time -v -o "$TIMEFILE" "$@" > "$OUT" 2> "$STDERR_FILE"
EXIT=$?

# Extract /usr/bin/time -v fields.
PEAK_RSS_KB=$(grep "Maximum resident set size" "$TIMEFILE" | awk -F': ' '{print $NF}')
WALL=$(grep "Elapsed (wall clock) time" "$TIMEFILE" | awk -F': ' '{print $NF}')
CPU_PCT=$(grep "Percent of CPU this job got" "$TIMEFILE" | awk -F': ' '{print $NF}')
USER_S=$(grep "User time (seconds)" "$TIMEFILE" | awk -F': ' '{print $NF}')
SYS_S=$(grep "System time (seconds)" "$TIMEFILE" | awk -F': ' '{print $NF}')
FS_IN=$(grep "File system inputs" "$TIMEFILE" | awk -F': ' '{print $NF}')
FS_OUT=$(grep "File system outputs" "$TIMEFILE" | awk -F': ' '{print $NF}')
VOL_CS=$(grep "Voluntary context switches" "$TIMEFILE" | awk -F': ' '{print $NF}')

cat <<EOF
{"name":"$NAME","exit":$EXIT,"peak_rss_kb":$PEAK_RSS_KB,"wall":"$WALL","cpu_pct":"$CPU_PCT","user_s":$USER_S,"sys_s":$SYS_S,"fs_in_blocks":$FS_IN,"fs_out_blocks":$FS_OUT,"vol_cs":$VOL_CS,"output":"$OUT","stderr":"$STDERR_FILE"}
EOF

rm -f "$TIMEFILE"
exit $EXIT
