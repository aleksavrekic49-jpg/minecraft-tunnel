package com.example.sshtunnel;

import com.jcraft.jsch.Channel;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/**
 * Opens an SSH reverse tunnel entirely in pure Java (JSch), equivalent to:
 *   ssh -p 443 -R0:localhost:LOCAL_PORT free.pinggy.io
 * No external ssh binary, no shell access, no ngrok. Runs inside the same
 * JVM as the Paper server, so it works under restricted Pterodactyl
 * containers that only allow plugin jars.
 *
 * CONFIGURE THESE THREE CONSTANTS FOR YOUR SETUP:
 */
public class SshTunnelPlugin extends JavaPlugin {

    // --- Pinggy (default). To use Serveo instead, set:
    //   SSH_HOST = "serveo.net", SSH_PORT = 22, SSH_USER = "serveo"
    private static final String SSH_HOST = "free.pinggy.io";
    private static final int SSH_PORT = 443;
    private static final String SSH_USER = "tunnel"; // pinggy ignores the username value itself

    private static final String LOCAL_HOST = "localhost";
    private static final int LOCAL_PORT = 25566; // <-- your Minecraft server port

    private Session session;
    private volatile boolean shuttingDown = false;

    @Override
    public void onEnable() {
        getLogger().info("Starting SSH reverse tunnel to " + SSH_HOST + ":" + SSH_PORT + " ...");
        connectTunnel();

        // Watchdog: check every 30s, reconnect if the session died
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
            session = jsch.getSession(SSH_USER, SSH_HOST, SSH_PORT);
            session.setConfig("StrictHostKeyChecking", "no");
            session.setServerAliveInterval(15000);
            session.connect(15000);

            // Request a remote forward with rport=0 -> server picks the public port.
            // -R 0:localhost:LOCAL_PORT
            int assigned = session.setPortForwardingR("", 0, LOCAL_HOST, LOCAL_PORT);
            getLogger().info("Remote forward established, server-assigned port: " + assigned);

            // Pinggy/Serveo print the actual public host:port as banner text over
            // a normal shell channel — open one and log whatever comes back.
            Channel shell = session.openChannel("shell");
            shell.connect(10000);
            InputStream in = shell.getInputStream();

            new Thread(() -> {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(in, StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        getLogger().info("[tunnel] " + line);
                    }
                } catch (Exception ignored) {
                    // stream closes when the session drops; watchdog handles reconnect
                }
            }, "ssh-tunnel-banner-reader").start();

        } catch (Exception e) {
            getLogger().severe("Failed to establish SSH tunnel: " + e.getMessage());
        }
    }
}
