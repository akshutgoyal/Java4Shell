#!/usr/bin/env bash
# Java4Shell lab launcher using plain Docker (no Compose required).
#
#   ./run.sh                 # all stages
#   ./run.sh trigger         # bounded trigger
#   ./run.sh control         # -XX:-UseBASE64Intrinsics
#   ./run.sh corrupt         # heap corruption + OOB read
#   ./run.sh leak            # JavaBleed disclosure
#   ./run.sh write           # chosen-value OOB write
#   ./run.sh --build all     # force a rebuild first
#
# Environment:
#   LAB_MODE=auto|native|sde   (default auto)
#   LAB_WARMUP=N               (default 1000)

set -euo pipefail
cd "$(dirname "$0")"

IMAGE="${IMAGE:-java4shell-lab:local}"
BUILD=0
if [ "${1:-}" = "--build" ]; then
    BUILD=1
    shift
fi
TEST="${1:-all}"

if [ "$BUILD" = 1 ] || ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -t "$IMAGE" .
fi

exec docker run --rm \
    --cap-add=SYS_PTRACE \
    --security-opt seccomp=unconfined \
    --network none \
    --tmpfs /tmp:rw,nosuid,nodev,size=512m \
    -e LAB_MODE="${LAB_MODE:-auto}" \
    -e LAB_WARMUP="${LAB_WARMUP:-1000}" \
    "$IMAGE" "$TEST"
