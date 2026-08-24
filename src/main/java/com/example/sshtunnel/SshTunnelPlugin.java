package com.example.sshtunnel;

import com.jcraft.jsch.ChannelShell;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.KeyPair;
import com.jcraft.jsch.Session;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Opens an SSH reverse tunnel entirely in pure Java (JSch), equivalent to:
 *   ssh -p 443 -R0:127.0.0.1:25566 LBdKSIzHRna+tcp@free.pinggy.io
 * On connect, parses Pinggy's announced tcp:// host:port from the banner
 * and pushes it into a Cloudflare SRV record so mc.yourdomain.com always
 * points at the current tunnel, even though Pinggy's address changes on
 * every reconnect.
 */
public class SshTunnelPlugin extends JavaPlugin {

    private static final String SSH_HOST = "free.pinggy.io";
    private static final int SSH_PORT = 443;
    private static final String SSH_USER = "LBdKSIzHRna+tcp"; // Pinggy access token as SSH username

    private static final String LOCAL_HOST = "127.0.0.1";
    private static final int LOCAL_PORT = 25566; // your Minecraft server port

    // --- Cloudflare config: fill these in with your real values ---
    private static final String CF_API_TOKEN = "YOUR_CLOUDFLARE_API_TOKEN";
    private static final String CF_ZONE_ID = "YOUR_CLOUDFLARE_ZONE_ID";
    private static final String CF_DOMAIN = "yourdomain.com";
    private static final String CF_SRV_SUBDOMAIN = "mc"; // -> mc.yourdomain.com
    private static final String CF_SRV_RECORD_NAME =
            "_minecraft._tcp." + CF_SRV_SUBDOMAIN + "." + CF_DOMAIN;
    private static final String CF_TARGET_NAME = CF_SRV_SUBDOMAIN + "." + CF_DOMAIN;

    private static final Pattern PINGGY_URL_PATTERN =
            Pattern.compile("tcp://([a-zA-Z0-9.\\-]+):(\\d+)");

    // --- DuckDNS config ---
    private static final String DUCKDNS_SUBDOMAIN = "everial"; // domains= param, no ".duckdns.org"
    private static final String DUCKDNS_TOKEN = "c9277dea-8245-41d7-80e6-7f82a0f7c3a1";
    private static final String DUCKDNS_FULL_DOMAIN = DUCKDNS_SUBDOMAIN + ".duckdns.org";

    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    private Session session;
    private volatile boolean shuttingDown = false;

    @Override
    public void onEnable() {
        getLogger().info("Starting SSH reverse tunnel to " + SSH_HOST + ":" + SSH_PORT + " ...");
        connectTunnel();

        getServer().getScheduler().runTaskTimerAsynchronously(this, () -> {
            if (!shuttingDown && (session == null || !session.isConnected())) {
                getLogger().warning("SSH tunnel disconnected, reconnecting...");
                connectTunnel();
            }
        }, 20L * 30, 20L * 30);
    }

    @Override
    public void onDisable() {
        shuttingDown = true;
        if (session != null && session.isConnected()) {
            session.disconnect();
        }
    }

    private void connectTunnel() {
        try {
            JSch jsch = new JSch();

            KeyPair keyPair = KeyPair.genKeyPair(jsch, KeyPair.RSA, 2048);
            ByteArrayOutputStream privateKeyOut = new ByteArrayOutputStream();
            ByteArrayOutputStream publicKeyOut = new ByteArrayOutputStream();
            keyPair.writePrivateKey(privateKeyOut);
            keyPair.writePublicKey(publicKeyOut, "");
            jsch.addIdentity("in-memory-key", privateKeyOut.toByteArray(), publicKeyOut.toByteArray(), null);
            keyPair.dispose();

            session = jsch.getSession(SSH_USER, SSH_HOST, SSH_PORT);
            session.setConfig("StrictHostKeyChecking", "no");
            session.setConfig("PreferredAuthentications", "publickey,password,keyboard-interactive");
            session.setServerAliveInterval(15000);
            session.connect(15000);
            getLogger().info("SSH session established, requesting remote forward...");

            session.setPortForwardingR("", 0, LOCAL_HOST, LOCAL_PORT);
            getLogger().info("Remote forward requested, opening shell channel for banner output...");

            ChannelShell shell = (ChannelShell) session.openChannel("shell");
            shell.setPty(true);
            shell.connect(10000);

            InputStream in = shell.getInputStream();
            OutputStream out = shell.getOutputStream();
            out.write('\n');
            out.flush();

            new Thread(() -> {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(in, StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        getLogger().info("[PINGGY] " + line);

                        Matcher matcher = PINGGY_URL_PATTERN.matcher(line);
                        if (matcher.find()) {
                            String host = matcher.group(1);
                            int port = Integer.parseInt(matcher.group(2));
                            updateCloudflareSrv(host, port);
                            updateDuckDns(host, port);
                        }
                    }
                } catch (Exception ignored) {
                    // stream closes when the session drops; watchdog handles reconnect
                }
            }, "ssh-tunnel-banner-reader").start();

        } catch (Exception e) {
            getLogger().severe("Failed to establish SSH tunnel: " + e);
            for (StackTraceElement el : e.getStackTrace()) {
                getLogger().severe("    at " + el);
            }
        }
    }

    /**
     * Looks up whether the SRV record already exists; PATCHes it if so,
     * otherwise POSTs a new one. Runs on the banner-reader thread, which is
     * already off the main server thread, so blocking HTTP calls here are fine.
     */
    private void updateCloudflareSrv(String targetHost, int targetPort) {
        try {
            String existingId = findExistingRecordId();
            String body = buildSrvBody(targetHost, targetPort);

            HttpRequest request;
            if (existingId != null) {
                request = HttpRequest.newBuilder()
                        .uri(URI.create("https://api.cloudflare.com/client/v4/zones/"
                                + CF_ZONE_ID + "/dns_records/" + existingId))
                        .header("Authorization", "Bearer " + CF_API_TOKEN)
                        .header("Content-Type", "application/json")
                        .method("PATCH", HttpRequest.BodyPublishers.ofString(body))
                        .timeout(Duration.ofSeconds(10))
                        .build();
            } else {
                request = HttpRequest.newBuilder()
                        .uri(URI.create("https://api.cloudflare.com/client/v4/zones/"
                                + CF_ZONE_ID + "/dns_records"))
                        .header("Authorization", "Bearer " + CF_API_TOKEN)
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(body))
                        .timeout(Duration.ofSeconds(10))
                        .build();
            }

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() / 100 == 2 && response.body().contains("\"success\":true")) {
                getLogger().info("[CLOUDFLARE] Updated SRV record to " + CF_TARGET_NAME + ":" + targetPort);
            } else {
                getLogger().warning("[CLOUDFLARE] Update failed (" + response.statusCode() + "): " + response.body());
            }
        } catch (Exception e) {
            getLogger().warning("[CLOUDFLARE] Error updating SRV record: " + e);
        }
    }

    /** Returns the existing SRV record's id, or null if none exists yet. */
    private String findExistingRecordId() throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://api.cloudflare.com/client/v4/zones/" + CF_ZONE_ID
                        + "/dns_records?type=SRV&name=" + CF_SRV_RECORD_NAME))
                .header("Authorization", "Bearer " + CF_API_TOKEN)
                .header("Content-Type", "application/json")
                .GET()
                .timeout(Duration.ofSeconds(10))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        Matcher idMatcher = Pattern.compile("\"id\":\"([a-f0-9]+)\"").matcher(response.body());
        return idMatcher.find() ? idMatcher.group(1) : null;
    }

    private String buildSrvBody(String targetHost, int targetPort) {
        return "{"
                + "\"type\":\"SRV\","
                + "\"name\":\"" + CF_SRV_RECORD_NAME + "\","
                + "\"ttl\":60,"
                + "\"data\":{"
                + "\"service\":\"_minecraft\","
                + "\"proto\":\"_tcp\","
                + "\"name\":\"" + CF_TARGET_NAME + "\","
                + "\"priority\":0,"
                + "\"weight\":5,"
                + "\"port\":" + targetPort + ","
                + "\"target\":\"" + targetHost + "\""
                + "}"
                + "}";
    }

    /**
     * Resolves Pinggy's hostname to an IP and points DUCKDNS_FULL_DOMAIN at it.
     * DuckDNS only accepts an A record (an IP), not a hostname, so the actual
     * join address players use is DUCKDNS_FULL_DOMAIN:port — the port still
     * has to be shared separately since DNS A records carry no port info.
     */
    private void updateDuckDns(String pinggyHost, int port) {
        try {
            String resolvedIp = InetAddress.getByName(pinggyHost).getHostAddress();

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("https://www.duckdns.org/update?domains=" + DUCKDNS_SUBDOMAIN
                            + "&token=" + DUCKDNS_TOKEN + "&ip=" + resolvedIp))
                    .GET()
                    .timeout(Duration.ofSeconds(10))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            String body = response.body().trim();

            if (response.statusCode() == 200 && body.startsWith("OK")) {
                getLogger().info("[DUCKDNS] Updated successfully! Join using: "
                        + DUCKDNS_FULL_DOMAIN + ":" + port);
            } else {
                getLogger().warning("[DUCKDNS] Update failed (" + response.statusCode() + "): " + body);
            }
        } catch (Exception e) {
            getLogger().warning("[DUCKDNS] Error updating record: " + e);
        }
    }
}
