package org.nmk30703.minip;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Secure Multi-Client Chat Server
 * Simplified version with network adapter selection using InetAddress
 */
public class SecureChatServer {
    private static final int DEFAULT_PORT = 30703;
    private static final String SECRET_KEY = "UniMAPMantap2025";
    private ServerSocket serverSocket;
    private boolean isRunning = false;
    private int port;
    private String bindAddress;
    private List<String> availableIPs;

    // Thread-safe collections for managing clients
    private ConcurrentHashMap<String, ClientHandler> clients = new ConcurrentHashMap<>();
    private ConcurrentHashMap<String, String> authenticatedUsers = new ConcurrentHashMap<>();
    private ExecutorService clientThreadPool = Executors.newCachedThreadPool();

    // Simple user database
    private HashMap<String, String> userDatabase = new HashMap<>();

    public SecureChatServer() {
        this(DEFAULT_PORT, null);
    }

    public SecureChatServer(int port, String bindAddress) {
        this.port = port;
        this.bindAddress = bindAddress;
        this.availableIPs = new ArrayList<>();
        initializeUserDatabase();
    }

    private void initializeUserDatabase() {
        userDatabase.put("admin", hashPassword("admin123"));
        userDatabase.put("user1", hashPassword("password1"));
        userDatabase.put("user2", hashPassword("password2"));
        userDatabase.put("guest", hashPassword("guest123"));
    }

    /**
     * Hash password using SHA-256
     */
    private String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashedBytes = md.digest(password.getBytes());
            return Base64.getEncoder().encodeToString(hashedBytes);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return password;
        }
    }

    /**
     * Discover available network IPs using InetAddress
     */
    public void discoverNetworkIPs() {
        availableIPs.clear();

        try {
            System.out.println("🔍 Discovering network IPs using InetAddress...");

            // Get localhost info
            InetAddress localhost = InetAddress.getLocalHost();
            System.out.println("System hostname: " + localhost.getHostName());
            System.out.println("System default IP: " + localhost.getHostAddress());

            // Scan network interfaces for all available IPs
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();

            while (interfaces.hasMoreElements()) {
                NetworkInterface ni = interfaces.nextElement();

                if (ni.isUp() && !ni.isLoopback()) {
                    Enumeration<InetAddress> addresses = ni.getInetAddresses();
                    while (addresses.hasMoreElements()) {
                        InetAddress addr = addresses.nextElement();

                        if (addr instanceof Inet4Address) {
                            String ip = addr.getHostAddress();
                            if (!availableIPs.contains(ip)) {
                                availableIPs.add(ip);
                            }
                        }
                    }
                }
            }

            // Add loopback (127.0.0.1) as last option
            if (!availableIPs.contains("127.0.0.1")) {
                availableIPs.add("127.0.0.1");
            }

            System.out.println("✅ Found " + availableIPs.size() + " available network IPs");

        } catch (Exception e) {
            System.err.println("Error discovering network IPs: " + e.getMessage());
            // Fallback IPs
            availableIPs.add("127.0.0.1");
            availableIPs.add("localhost");
        }
    }

    /**
     * Display available network IPs
     */
    public void displayAvailableIPs() {
        System.out.println("\n🌐 Available Network IPs:");
        System.out.println("=" .repeat(30));

        for (int i = 0; i < availableIPs.size(); i++) {
            String ip = availableIPs.get(i);
            System.out.println((i + 1) + ". " + ip);
        }
        System.out.println("=" .repeat(30));
    }

    /**
     * Get IP type description - removed, not needed
     */

    /**
     * Select network adapter interactively
     */
    public String selectNetworkAdapter() {
        Scanner scanner = new Scanner(System.in);

        while (true) {
            displayAvailableIPs();
            System.out.print("\nSelect IP number (1-" + availableIPs.size() + ") or 'all' for all interfaces: ");

            String input = scanner.nextLine().trim();

            if (input.equalsIgnoreCase("all")) {
                return null; // Bind to all interfaces
            }

            try {
                int choice = Integer.parseInt(input);
                if (choice >= 1 && choice <= availableIPs.size()) {
                    String selectedIP = availableIPs.get(choice - 1);
                    System.out.println("✅ Selected: " + selectedIP);
                    return selectedIP;
                }
            } catch (NumberFormatException e) {
                // Invalid input
            }

            System.out.println("❌ Invalid selection. Please try again.");
        }
    }

    /**
     * Start the server
     */
    public void startServer() {
        try {
            if (bindAddress != null && !bindAddress.isEmpty()) {
                InetAddress bindAddr = InetAddress.getByName(bindAddress);
                serverSocket = new ServerSocket(port, 50, bindAddr);
                System.out.println("🚀 Server started on " + bindAddress + ":" + port);
            } else {
                serverSocket = new ServerSocket(port);
                System.out.println("🚀 Server started on all interfaces:" + port);
            }

            isRunning = true;

            System.out.println("🔌 Port: " + port);
            System.out.println("📋 Users: " + userDatabase.keySet());
            System.out.println("🔐 Encryption: AES-128");
            System.out.println("Waiting for clients...\n");

            while (isRunning) {
                try {
                    Socket clientSocket = serverSocket.accept();
                    System.out.println("📥 Connection from: " + clientSocket.getInetAddress().getHostAddress());

                    ClientHandler clientHandler = new ClientHandler(clientSocket);
                    clientThreadPool.submit(clientHandler);

                } catch (IOException e) {
                    if (isRunning) {
                        System.err.println("Error accepting connection: " + e.getMessage());
                    }
                }
            }
        } catch (IOException e) {
            System.err.println("❌ Error starting server: " + e.getMessage());
        }
    }

    /**
     * Stop the server
     */
    public void stopServer() {
        isRunning = false;
        try {
            if (serverSocket != null) {
                serverSocket.close();
            }
            clientThreadPool.shutdown();
            System.out.println("🛑 Server stopped.");
        } catch (IOException e) {
            System.err.println("Error stopping server: " + e.getMessage());
        }
    }

    /**
     * Broadcast message to all clients except sender
     */
    private void broadcastMessage(String message, String senderUsername) {
        for (Map.Entry<String, ClientHandler> entry : clients.entrySet()) {
            String username = entry.getKey();
            ClientHandler client = entry.getValue();

            if (!username.equals(senderUsername)) {
                client.sendMessage(message);
            }
        }
    }

    /**
     * Send private message
     */
    private void sendPrivateMessage(String message, String targetUsername, String senderUsername) {
        ClientHandler targetClient = clients.get(targetUsername);
        if (targetClient != null) {
            targetClient.sendMessage("[PRIVATE from " + senderUsername + "]: " + message);
            ClientHandler senderClient = clients.get(senderUsername);
            if (senderClient != null) {
                senderClient.sendMessage("[PRIVATE to " + targetUsername + "]: " + message);
            }
        } else {
            ClientHandler senderClient = clients.get(senderUsername);
            if (senderClient != null) {
                senderClient.sendMessage("❌ User '" + targetUsername + "' not found.");
            }
        }
    }

    /**
     * Client handler class
     */
    private class ClientHandler implements Runnable {
        private Socket clientSocket;
        private BufferedReader input;
        private PrintWriter output;
        private String username;
        private boolean isAuthenticated = false;
        private Cipher encryptCipher;
        private Cipher decryptCipher;

        public ClientHandler(Socket socket) {
            this.clientSocket = socket;
            setupEncryption();
        }

        private void setupEncryption() {
            try {
                SecretKeySpec secretKey = new SecretKeySpec(SECRET_KEY.getBytes(), "AES");
                encryptCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                decryptCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                encryptCipher.init(Cipher.ENCRYPT_MODE, secretKey);
                decryptCipher.init(Cipher.DECRYPT_MODE, secretKey);
            } catch (Exception e) {
                System.err.println("❌ Error setting up encryption: " + e.getMessage());
            }
        }

        private String encrypt(String message) {
            try {
                byte[] encrypted = encryptCipher.doFinal(message.getBytes());
                return Base64.getEncoder().encodeToString(encrypted);
            } catch (Exception e) {
                System.err.println("Error encrypting: " + e.getMessage());
                return message;
            }
        }

        private String decrypt(String encryptedMessage) {
            try {
                byte[] decoded = Base64.getDecoder().decode(encryptedMessage);
                byte[] decrypted = decryptCipher.doFinal(decoded);
                return new String(decrypted);
            } catch (Exception e) {
                System.err.println("Error decrypting: " + e.getMessage());
                return encryptedMessage;
            }
        }

        @Override
        public void run() {
            try {
                input = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                output = new PrintWriter(clientSocket.getOutputStream(), true);

                sendMessage("🔐 Welcome to Secure Chat Server!");
                sendMessage("Please authenticate to continue.");

                if (authenticate()) {
                    sendMessage("✅ Authentication successful! Welcome " + username + "!");
                    sendMessage("📝 Commands: /list, /private <user> <message>, /quit");

                    broadcastMessage("📢 " + username + " joined the chat!", username);

                    String encryptedMessage;
                    while ((encryptedMessage = input.readLine()) != null) {
                        String message = decrypt(encryptedMessage);

                        if (message.equals("/quit")) {
                            break;
                        } else if (message.equals("/list")) {
                            sendMessage("👥 Online users: " + clients.keySet());
                        } else if (message.startsWith("/private ")) {
                            handlePrivateMessage(message);
                        } else {
                            String chatMessage = "💬 " + username + ": " + message;
                            System.out.println(chatMessage);
                            broadcastMessage(chatMessage, username);
                        }
                    }
                }

            } catch (IOException e) {
                System.err.println("Error handling client: " + e.getMessage());
            } finally {
                cleanup();
            }
        }

        private boolean authenticate() {
            try {
                sendMessage("Username: ");
                String inputUsername = decrypt(input.readLine());

                sendMessage("Password: ");
                String inputPassword = decrypt(input.readLine());

                String hashedInput = hashPassword(inputPassword);

                if (userDatabase.containsKey(inputUsername) &&
                        userDatabase.get(inputUsername).equals(hashedInput)) {

                    if (clients.containsKey(inputUsername)) {
                        sendMessage("❌ User already logged in!");
                        return false;
                    }

                    this.username = inputUsername;
                    this.isAuthenticated = true;
                    clients.put(username, this);
                    authenticatedUsers.put(username, clientSocket.getInetAddress().getHostAddress());

                    System.out.println("✅ User '" + username + "' authenticated from " +
                            clientSocket.getInetAddress().getHostAddress());
                    return true;
                } else {
                    sendMessage("❌ Invalid credentials!");
                    return false;
                }
            } catch (IOException e) {
                System.err.println("Error during authentication: " + e.getMessage());
                return false;
            }
        }

        private void handlePrivateMessage(String command) {
            String[] parts = command.split(" ", 3);
            if (parts.length >= 3) {
                String targetUser = parts[1];
                String message = parts[2];
                sendPrivateMessage(message, targetUser, username);
            } else {
                sendMessage("❌ Usage: /private <username> <message>");
            }
        }

        public void sendMessage(String message) {
            if (output != null) {
                String encryptedMessage = encrypt(message);
                output.println(encryptedMessage);
            }
        }

        private void cleanup() {
            try {
                if (username != null && isAuthenticated) {
                    clients.remove(username);
                    authenticatedUsers.remove(username);
                    broadcastMessage("📢 " + username + " left the chat.", username);
                    System.out.println("👋 User '" + username + "' disconnected");
                }

                if (input != null) input.close();
                if (output != null) output.close();
                if (clientSocket != null) clientSocket.close();

            } catch (IOException e) {
                System.err.println("Error cleaning up: " + e.getMessage());
            }
        }
    }

    /**
     * Display usage information
     */
    private static void showUsage() {
        System.out.println("Usage: java SecureChatServer [options]");
        System.out.println("Options:");
        System.out.println("  -p <port>     Port number (default: 30703)");
        System.out.println("  -b <address>  Bind to specific IP address (skips selection)");
        System.out.println("  -i            Show available IPs and exit");
        System.out.println("  -h            Show help");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  java SecureChatServer                    # Shows IP selection menu");
        System.out.println("  java SecureChatServer -b 192.168.1.100   # Bind directly to IP");
        System.out.println("  java SecureChatServer -p 8080            # Custom port with selection");
    }

    /**
     * Main method
     */
    public static void main(String[] args) {
        int port = DEFAULT_PORT;
        String bindAddress = null;
        boolean showIPs = false;
        boolean skipSelection = false;

        // Parse arguments
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-p":
                    if (i + 1 < args.length) {
                        try {
                            port = Integer.parseInt(args[++i]);
                        } catch (NumberFormatException e) {
                            System.err.println("Invalid port: " + args[i]);
                            return;
                        }
                    }
                    break;
                case "-b":
                    if (i + 1 < args.length) {
                        bindAddress = args[++i];
                        skipSelection = true; // Skip selection if IP is provided
                    }
                    break;
                case "-i":
                    showIPs = true;
                    break;
                case "-h":
                    showUsage();
                    return;
                default:
                    System.err.println("Unknown option: " + args[i]);
                    showUsage();
                    return;
            }
        }

        SecureChatServer server = new SecureChatServer(port, bindAddress);
        server.discoverNetworkIPs();

        if (showIPs) {
            server.displayAvailableIPs();
            return;
        }

        // Always show selection menu unless IP is already provided with -b
        if (!skipSelection) {
            bindAddress = server.selectNetworkAdapter();
            server.bindAddress = bindAddress;
        }

        System.out.println("🔐 Secure Chat Server");
        System.out.println("====================");
        if (bindAddress != null) {
            System.out.println("🌐 Binding to: " + bindAddress + ":" + port);
        } else {
            System.out.println("🌐 Binding to: All interfaces:" + port);
        }
        System.out.println("====================\n");

        // Graceful shutdown
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("\n🛑 Shutting down server...");
            server.stopServer();
        }));

        server.startServer();
    }
}