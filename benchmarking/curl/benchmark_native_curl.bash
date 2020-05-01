#!/bin/bash
if [ "$#" -ne 1 ]; then
    echo "Illegal number of parameters"
    echo "Pass the target IP as sole argument"
    exit 1
fi

if [ ! -d results ]; then
    mkdir results
fi

DST_IP="$1"
PROTOS=( "http" )
DST_PORTS=( 80 )

BIN=~/benchmarking/curl-7.47.0/build/src/curl

RUNS=50

BIN_OPTS="-4 --insecure -o /dev/null -s -w \"@curl_format.txt\""

FILES=( "/" )
# TODO: you have to host the corresponding files; "one" = 1MB;
#FILES=( 1KB.data 10KB.data 100KB.data one.data ten.data twenty.data fourty.data hundred.data thousand.data )

LOG_HTTP="./results/`date \"+%Y_%m_%d__%H_%M_%S\"`_curl_native_http.log"

EXEC_CMD="sudo -E nice -n -20 ${BIN} $BIN_OPTS"

function run_curl_test() {
    # $1: target IP
    # $2: target protocol
    # $3: target port
    # $4: log file

#    echo "IP: \"${1}\"" >> $4
#    echo "Port: \"${3}\"" >> $4
#    echo "FILES: \"${FILES[@]}\"" >> $4
#    echo "MODE: \"++SENG\"" >> $4

    # CSV header
    echo "URL;Total Time [sec];Download Size [Bytes]" > $4

    echo "${2}://${1}:${3}"

    for F in "${FILES[@]}"
    do
        echo "File $F"
        for i in `seq ${RUNS}`
        do
            echo "Iteration $i"
            date
            eval "$EXEC_CMD ${2}://${1}:${3}/${F}" >> $4
        done
    done

    # Remove 'invalid pointer' message
    sed -i '/invalid pointer/d' $4
    sed -i '/Internal memory fault at 0x0/d' $4
}

# HTTP
run_curl_test "$DST_IP" "${PROTOS[0]}" ${DST_PORTS[0]} "$LOG_HTTP"
