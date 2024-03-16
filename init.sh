#!/bin/bash
if (( $EUID != 0 )); then
    echo "Please run as root"
    exit
fi

function cleanup {
    kill $WHISPER_PID
}

trap cleanup INT EXIT

target/debug/whisper &
WHISPER_PID=$!
ip link set up dev wisp0
ip addr add 192.168.2.100/24 dev wisp0

wait $WHISPER_PID