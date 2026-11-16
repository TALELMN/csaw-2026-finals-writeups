#!/usr/bin/env bash
# Dead Air Observatory (CSAW CTF Finals 2026, rev 500) — staged brute-forcer.
#
# The binary checks the three observations IN ORDER and exits on the first
# failure, so each 64^3 stage can be solved independently instead of searching
# 64^9 at once.
#
#   ./bf.sh 1                      -> finds observation 1, e.g. "51 7 26"
#   ./bf.sh 2 51 7 26              -> finds observation 2
#   ./bf.sh 3 51 7 26 4 61 11      -> finds observation 3, prints the flag
#
# Reconstruction note: the original bf1.sh was not preserved; this reproduces the
# documented method. Parallelise with `-P` below if you have cores to spare.
set -u

BIN=${BIN:-./observatory}
JOBS=${JOBS:-12}

STAGE=$1; shift
PREFIX=("$@")

# Everything after our triple is padding: the program never reaches it, because
# it exits as soon as our stage fails.
pad=$(( (3 - STAGE) * 3 ))
PAD=()
for ((i = 0; i < pad; i++)); do PAD+=(0); done

try() {
    out=$("$BIN" "${PREFIX[@]}" "$1" "$2" "$3" "${PAD[@]}" 2>/dev/null)
    if grep -q "Observation $STAGE: carrier locked" <<<"$out"; then
        echo "[+] observation $STAGE = $1 $2 $3"
        [[ $STAGE -eq 3 ]] && grep -o 'csaw{[^}]*}' <<<"$out"
        return 0
    fi
    return 1
}
export -f try
export BIN STAGE
export PREFIX_STR="${PREFIX[*]}"

for ((a = 0; a < 64; a++)); do
    for ((b = 0; b < 64; b++)); do
        for ((c = 0; c < 64; c++)); do
            echo "$a $b $c"
        done
    done
done | xargs -P "$JOBS" -n 3 bash -c 'try "$@" && kill -INT 0' _
