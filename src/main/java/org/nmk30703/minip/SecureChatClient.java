package org.nmk30703.minip;

import java.io.*;
import java.net.*;
import java.util.Scanner;
import java.util.Enumeration;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Base64;

/**
 * Secure Chat Client
 * Connects to the secure chat server with encryption
 * Now supports auto-detection of network IP using InetAddress
 */
public class SecureChatClient {
    private static final String DEFAULT_SERVER_HOST = "localhost";
    private static final int DEFAULT_SERVER_PORT = 30703;
    private static final String SECRET_KEY = "UniMAPMantap2025"; // Must match server

    private Socket socket;
    private BufferedReader input;
    private PrintWriter output;
    private Scanner scanner;
    private boolean isConnected = false;
    private Cipher encryptCipher;
    private Cipher decryptCipher;
    private String username;
    private String serverHost;
    private int serverPort;
    private String detectedNetworkIP;

    public SecureChatClient() {
        this(DEFAULT_SERVER_HOST, DEFAULT_SERVER_PORT);
    }

    public SecureChatClient(String serverHost, int serverPort) {
        this.serverHost = serverHost;
        this.serverPort = serverPort;
        scanner = new Scanner(System.in);
        detectNetworkIP();
        setupEncryption();
    }

    /**
     * Detect network IP using InetAddress class (as per NMK30703 lab module)
     */
    private void detectNetworkIP() {
        try {
            // Method 1: Get localhost address (as per lecture)
            InetAddress localhost = InetAddress.getLocalHost();

            // Check if localhost gives us a proper network IP
            String localhostIP = localhost.getHostAddress();
            if (!localhostIP.equals("127.0.0.1") && !localhostIP.equals("localhost")) {
                detectedNetworkIP = localhostIP;
                // Set as default server host if not explicitly set
                if (serverHost.equals(DEFAULT_SERVER_HOST)) {
                    serverHost = localhostIP;
                }
                return;
            }

            // Method 2: Scan network interfaces for better IP detection
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface ni = interfaces.nextElement();

                if (ni.isUp() && !ni.isLoopback() && !ni.isVirtual()) {
                    Enumeration<InetAddress> addresses = ni.getInetAddresses();
                    while (addresses.hasMoreElements()) {
                        InetAddress addr = addresses.nextElement();

                        if (addr instanceof Inet4Address && !addr.isLoopbackAddress()) {
                            String ip = addr.getHostAddress();

                            // Prefer private network addresses
                            if (ip.startsWith("192.168.") || ip.startsWith("10.") ||
                                    (ip.startsWith("172.") &&
                                            Integer.parseInt(ip.split("\\.")[1]) >= 16 &&
                                            Integer.parseInt(ip.split("\\.")[1]) <= 31)) {
                                detectedNetworkIP = ip;
                                // Set as default server host if not explicitly set
                                if (serverHost.equals(DEFAULT_SERVER_HOST)) {
                                    serverHost = ip;
                                }
                                return;
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Silent handling - no need to show error for network detection
        }

        // Final fallback to localhost
        if (detectedNetworkIP == null) {
            detectedNetworkIP = "localhost";
            if (serverHost.equals(DEFAULT_SERVER_HOST)) {
                serverHost = "localhost";
            }
        }
    }

    /**
     * Setup AES encryption (same as server)
     */
    private void setupEncryption() {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(SECRET_KEY.getBytes(), "AES");
            encryptCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            decryptCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            encryptCipher.init(Cipher.ENCRYPT_MODE, secretKey);
            decryptCipher.init(Cipher.DECRYPT_MODE, secretKey);
        } catch (Exception e) {
            System.err.println("❌ Error setting up encryption: " + e.getMessage());
            System.exit(1);
        }
    }

    /**
     * Encrypt message
     */
    private String encrypt(String message) {
        try {
            byte[] encrypted = encryptCipher.doFinal(message.getBytes());
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            System.err.println("Error encrypting message: " + e.getMessage());
            return message;
        }
    }

    /**
     * Decrypt message
     */
    private String decrypt(String encryptedMessage) {
        try {
            byte[] decoded = Base64.getDecoder().decode(encryptedMessage);
            byte[] decrypted = decryptCipher.doFinal(decoded);
            return new String(decrypted);
        } catch (Exception e) {
            System.err.println("Error decrypting message: " + e.getMessage());
            return encryptedMessage;
        }
    }

    /**
     * Get server connection details interactively
     */
    private void getServerDetails() {
        System.out.print("Enter server IP address (current: " + serverHost + "): ");
        String input = scanner.nextLine().trim();
        if (!input.isEmpty()) {
            serverHost = input;
        }

        System.out.print("Enter server port (current: " + serverPort + "): ");
        input = scanner.nextLine().trim();
        if (!input.isEmpty()) {
            try {
                serverPort = Integer.parseInt(input);
            } catch (NumberFormatException e) {
                System.err.println("Invalid port number, using current: " + serverPort);
            }
        }
    }

    /**
     * Test connection to server
     */
    private boolean testConnection() {
        try {
            System.out.println("🔍 Testing connection to " + serverHost + ":" + serverPort + "...");
            Socket testSocket = new Socket();
            testSocket.connect(new InetSocketAddress(serverHost, serverPort), 5000); // 5 second timeout
            testSocket.close();
            System.out.println("✅ Connection test successful!");
            return true;
        } catch (IOException e) {
            System.err.println("❌ Connection test failed: " + e.getMessage());
            return false;
        }
    }

    /**
     * Connect to the server
     */
    public void connectToServer() {
        try {
            System.out.println("🔗 Connecting to server...");

            socket = new Socket(serverHost, serverPort);
            input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            output = new PrintWriter(socket.getOutputStream(), true);
            isConnected = true;

            System.out.println("✅ Connected successfully!");

            // Start thread to listen for server messages
            Thread serverListener = new Thread(this::listenForServerMessages);
            serverListener.setDaemon(true);
            serverListener.start();

            // Handle authentication
            authenticate();

            // Start sending messages
            sendMessages();

        } catch (IOException e) {
            System.err.println("❌ Connection failed: " + e.getMessage());
            System.err.println("💡 Check server is running on " + serverHost + ":" + serverPort);
        }
    }

    /**
     * Handle authentication with server
     */
    private void authenticate() {
        try {
            // Wait for server prompts and respond
            Thread.sleep(500); // Give server time to send welcome messages

            username = scanner.nextLine();
            sendEncryptedMessage(username);

            String password = scanner.nextLine();
            sendEncryptedMessage(password);

            // Give time for authentication response
            Thread.sleep(1000);

        } catch (InterruptedException e) {
            System.err.println("Authentication interrupted: " + e.getMessage());
        }
    }

    /**
     * Listen for messages from server
     */
    private void listenForServerMessages() {
        try {
            String encryptedMessage;
            while (isConnected && (encryptedMessage = input.readLine()) != null) {
                String message = decrypt(encryptedMessage);

                // Check if it's a server prompt (no decryption needed for prompts)
                if (message.endsWith(": ")) {
                    System.out.print(message);
                } else {
                    System.out.println(message);
                }
            }
        } catch (IOException e) {
            if (isConnected) {
                System.err.println("❌ Lost connection to server: " + e.getMessage());
                System.err.println("💡 Try reconnecting or check your network connection");
            }
        }
    }

    /**
     * Send messages to server
     */
    private void sendMessages() {
        System.out.println("\n📝 Type '/help' for commands or '/quit' to exit.");
        System.out.println("💬 You can start chatting now!");

        String message;
        while (isConnected && (message = scanner.nextLine()) != null) {
            if (message.equals("/quit")) {
                sendEncryptedMessage(message);
                break;
            } else if (message.equals("/help")) {
                showHelp();
            } else if (message.equals("/info")) {
                showConnectionInfo();
            } else if (!message.trim().isEmpty()) {
                sendEncryptedMessage(message);
            }
        }

        disconnect();
    }

    /**
     * Show help commands
     */
    private void showHelp() {
        System.out.println("\n📋 Available Commands:");
        System.out.println("  /list                    - Show online users");
        System.out.println("  /private <user> <msg>    - Send private message");
        System.out.println("  /info                    - Show connection info");
        System.out.println("  /quit                    - Exit chat");
        System.out.println("  /help                    - Show this help");
        System.out.println("  <message>                - Send public message\n");
    }

    /**
     * Show connection information
     */
    private void showConnectionInfo() {
        if (isConnected && socket != null) {
            System.out.println("\n🌐 Connection Information:");
            System.out.println("  Server: " + serverHost + ":" + serverPort);
            System.out.println("  Your IP: " + detectedNetworkIP);
            System.out.println("  Username: " + username);
            System.out.println("  Status: Connected ✅\n");
        } else {
            System.out.println("\n❌ Not connected to server");
            System.out.println("🏠 Your IP: " + detectedNetworkIP + "\n");
        }
    }

    /**
     * Send encrypted message to server
     */
    private void sendEncryptedMessage(String message) {
        if (output != null && isConnected) {
            String encryptedMessage = encrypt(message);
            output.println(encryptedMessage);
        }
    }

    /**
     * Disconnect from server
     */
    public void disconnect() {
        isConnected = false;
        try {
            if (input != null) input.close();
            if (output != null) output.close();
            if (socket != null) socket.close();
            System.out.println("👋 Disconnected from server. Goodbye!");
        } catch (IOException e) {
            System.err.println("Error disconnecting: " + e.getMessage());
        }
    }

    /**
     * Display usage information
     */
    private static void showUsage() {
        System.out.println("Usage: java SecureChatClient [options]");
        System.out.println("Options:");
        System.out.println("  -h <address>   Server IP address (default: auto-detected)");
        System.out.println("  -p <port>      Server port (default: 30703)");
        System.out.println("  -i             Interactive mode (ask for server details)");
        System.out.println("  --help         Show this help message");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  java SecureChatClient                    # Use auto-detected IP");
        System.out.println("  java SecureChatClient -h 192.168.1.100   # Connect to specific IP");
        System.out.println("  java SecureChatClient -i                 # Interactive mode");
        System.out.println("  java SecureChatClient -p 8080            # Custom port");
    }

    /**
     * Main method to start the client
     */
    public static void main(String[] args) {
        String serverHost = DEFAULT_SERVER_HOST; // Will be auto-detected
        int serverPort = DEFAULT_SERVER_PORT;
        boolean interactive = false;

        // Parse command line arguments
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-h":
                    if (i + 1 < args.length) {
                        serverHost = args[++i];
                    } else {
                        System.err.println("Server address required after -h");
                        return;
                    }
                    break;
                case "-p":
                    if (i + 1 < args.length) {
                        try {
                            serverPort = Integer.parseInt(args[++i]);
                        } catch (NumberFormatException e) {
                            System.err.println("Invalid port number: " + args[i]);
                            return;
                        }
                    } else {
                        System.err.println("Port number required after -p");
                        return;
                    }
                    break;
                case "-i":
                    interactive = true;
                    break;
                case "--help":
                    showUsage();
                    return;
                default:
                    System.err.println("Unknown option: " + args[i]);
                    showUsage();
                    return;
            }
        }

        System.out.println("🔐 Secure Chat Client - Auto Network Detection");
        System.out.println("===============================================");
        System.out.println("Available test accounts:");
        System.out.println("  Username: admin,  Password: admin123");
        System.out.println("  Username: user1,  Password: password1");
        System.out.println("  Username: user2,  Password: password2");
        System.out.println("  Username: guest,  Password: guest123");
        System.out.println("===============================================\n");

        SecureChatClient client = new SecureChatClient(serverHost, serverPort);

        // Interactive mode to get server details
        if (interactive) {
            client.getServerDetails();
        }

        // Test connection first
        if (!client.testConnection()) {
            System.err.println("❌ Cannot connect to server. Please check:");
            System.err.println("   1. Server is running on " + client.serverHost + ":" + client.serverPort);
            System.err.println("   2. Network connectivity");
            System.err.println("   3. Firewall settings");
            System.err.println("   4. Your IP: " + client.detectedNetworkIP);
            return;
        }

        // Handle graceful shutdown
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("\n🛑 Client shutting down...");
            client.disconnect();
        }));

        client.connectToServer();
    }
}