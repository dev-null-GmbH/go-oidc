import java.net.HttpURLConnection;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

// Fixed public dependency probe; never print addresses, environment or exception messages.
class ConformanceNetworkProbe {
    private static final URI POM = URI.create("https://repo.maven.apache.org/maven2/org/springframework/boot/spring-boot-starter-parent/4.0.7/spring-boot-starter-parent-4.0.7.pom");

    public static void main(String[] args) {
        preference("java.net.preferIPv4Stack", "prefer_ipv4_stack", "ipv4");
        preference("java.net.preferIPv6Addresses", "prefer_ipv6_addresses", "ipv6");
        long started = System.nanoTime();
        try {
            InetAddress[] addresses = CompletableFuture.supplyAsync(() -> {
                try {
                    return InetAddress.getAllByName(POM.getHost());
                } catch (Exception failure) {
                    throw new CompletionException(failure);
                }
            }).get(5, TimeUnit.SECONDS);
            report("dns", "default", "resolved", started, null);
            int ipv4 = 0, ipv6 = 0;
            for (InetAddress address : addresses) {
                boolean v4 = address instanceof Inet4Address;
                if ((v4 ? ++ipv4 : ++ipv6) > 2) continue;
                probe(address, v4 ? "ipv4" : "ipv6");
            }
            if (ipv4 == 0) report("dns", "ipv4", "absent", System.nanoTime(), null);
            if (ipv6 == 0) report("dns", "ipv6", "absent", System.nanoTime(), null);
        } catch (Exception failure) {
            report("dns", "default", "failed", started, failure);
        }
        started = System.nanoTime();
        HttpURLConnection connection = null;
        try {
            connection = (HttpURLConnection) POM.toURL().openConnection();
            connection.setConnectTimeout(3000);
            connection.setReadTimeout(3000);
            connection.setInstanceFollowRedirects(false);
            report("https_get", "default", "http_" + connection.getResponseCode(), started, null);
        } catch (Exception failure) {
            report("https_get", "default", "failed", started, failure);
        } finally {
            if (connection != null) connection.disconnect();
        }
    }

    private static void probe(InetAddress address, String family) {
        long started = System.nanoTime();
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(address, 443), 3000);
            report("tcp443", family, "connected", started, null);
        } catch (Exception failure) {
            report("tcp443", family, "failed", started, failure);
        }
    }

    private static void preference(String property, String phase, String family) {
        String value = System.getProperty(property, "unset");
        String status = switch (value) {
            case "unset", "true", "false", "system" -> value;
            default -> "other";
        };
        report(phase, family, status, System.nanoTime(), null);
    }

    private static void report(String phase, String family, String status, long started, Throwable failure) {
        while ((failure instanceof ExecutionException || failure instanceof CompletionException)
                && failure.getCause() != null) failure = failure.getCause();
        System.out.printf("phase=%s family=%s status=%s duration_ms=%d exception=%s%n",
                phase, family, status, (System.nanoTime() - started) / 1_000_000,
                failure == null ? "none" : failure.getClass().getSimpleName());
    }
}
