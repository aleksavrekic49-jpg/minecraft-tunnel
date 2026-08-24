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
import java.nio.charset.StandardCharsets;

/**
 * Opens an SSH reverse tunnel entirely in pure Java (JSch), equivalent to:
 *   ssh -p 443 -R0:127.0.0.1:25566 LBdKSIzHRna@free.pinggy.io
 * No external ssh binary, no shell access needed on the host, no ngrok.
 * Runs inside the same JVM as the Paper server.
 */
public class SshTunnelPlugin extends JavaPlugin {

    private static final String SSH_HOST = "free.pinggy.io";
    private static final int SSH_PORT = 443;
    private static final String SSH_USER = "LBdKSIzHRna+tcp"; // Pinggy access token as SSH username

    private static final String LOCAL_HOST = "127.0.0.1";
    private static final int LOCAL_PORT = 25566; // your Minecraft server port

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

            // Fresh in-memory keypair for the SSH handshake itself. Pinggy's actual
            // identity/authorization comes from SSH_USER (the access token), not
            // from this key being pre-registered anywhere.
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

            // -R 0:127.0.0.1:LOCAL_PORT — server picks the public port.
            // This JSch build's setPortForwardingR returns void, so the assigned
            // port/URL only comes back via the banner text captured below.
            session.setPortForwardingR("", 0, LOCAL_HOST, LOCAL_PORT);
            getLogger().info("Remote forward requested, opening shell channel for banner output...");

            // Pinggy only prints its welcome banner (with the tcp:// URL) to an
            // interactive session — that requires a pty, not just a bare channel.
            ChannelShell shell = (ChannelShell) session.openChannel("shell");
            shell.setPty(true);
            shell.connect(10000);

            InputStream in = shell.getInputStream();
            OutputStream out = shell.getOutputStream();
            // Some servers wait for a newline before flushing their banner.
            out.write('\n');
            out.flush();

            new Thread(() -> {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(in, StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        getLogger().info("[PINGGY] " + line);
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
}
