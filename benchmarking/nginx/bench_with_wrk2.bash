#!/bin/bash
if [ "$#" -ne 1 ]; then
    echo "Illegal number of parameters"
    echo "Pass the target IP (NGINX) as sole argument"
    exit 1
fi

if [ ! -d results ]; then
    mkdir results
fi

FILES=( "" )
#LOADS=( `seq 1000 1000 20000` ) # LibOS/-SENG
#LOADS=( `seq 1000 3000 52000` ) # native
LOADS=( `seq 1000 3000 25000` `seq 26000 1000 40000` `seq 43000 3000 49000` ) # SDK-SENG full run

RUNS=5

PROTO="http"
DST_IP="$1"
DST_PORT=4711

WRK2=../wrk2-e0109df5b9de09251adb5f5848f223fbee2aa9f5/wrk

LOG_FILE="./results/`date \"+%Y_%m_%d__%H_%M_%S\"`_${PROTO}_wrk2.csv"

echo "Path;WorkLoad [req/sec];RealizedLoad [req/sec];Latency Mean [ms];Latency stdev" > "${LOG_FILE}"

for f in "${FILES[@]}"
do
    echo "Target path: \"/${f}\""
    for wl in "${LOADS[@]}"
    do
        echo "Work Load: ${wl}"
        for i in `seq $RUNS`
        do
            echo "Iteration: ${i}"
            echo -n "${f};${wl};" >> "${LOG_FILE}"
            ${WRK2} --threads 2 --connections 100 --duration "10s" --rate $wl "${PROTO}://${DST_IP}:${DST_PORT}/${f}" --latency | tr -d '\n' | sed -n 's/.*#\[Mean *= *\([0-9]*\.[0-9]*\), StdDeviation *= * \([0-9]*\.[0-9]*\)].*Requests\/sec: *\([0-9]*\.[0-9]*\).*/\3;\1;\2\n/p' >> "${LOG_FILE}" || exit 1
        done
    done
done
