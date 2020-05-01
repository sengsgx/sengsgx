#!/bin/bash
if [ "$#" -ne 1 ]; then
    echo "Illegal number of parameters"
    echo "Pass the target IP as sole argument"
    exit 1
fi

DST_IP="$1"
BIN="../iperf-3.1.3/build/bin/iperf3"

ITERATIONS=5

IPERF_OPTS="--reverse --client $DST_IP --len 8K"
BANDWIDTH_LIST=( `seq 100 100 1000` )

IPERF="sudo -E nice -n -20 ${BIN} $IPERF_OPTS"

# Run iPerf3
for b in "${BANDWIDTH_LIST[@]}"
do
    echo "Bandwidth: $b"
    for i in `seq 1 ${ITERATIONS}`
    do
        echo "Iteration: $i"
        date
        eval "$IPERF --bandwidth ${b}M" >/dev/null 2>/dev/null #|| exit 1
        sleep 1
    done
done
