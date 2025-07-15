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
 * Handles multiple client connections with encryption and authentication
 */
public class SecureChatServer {
    private static final int PORT = 30703;
    private static final String SECRET_KEY = "UniMAPMantap2025"; // 16 characters for AES
    private ServerSocket serverSocket;
    private boolean isRunning = false;

    // Thread-safe collections for managing clients
    private ConcurrentHashMap<String, ClientHandler> clients = new ConcurrentHashMap<>();
    private ConcurrentHashMap<String, String> authenticatedUsers = new ConcurrentHashMap<>();
    private ExecutorService clientThreadPool = Executors.newCachedThreadPool();

    // Simple user database (in real application, use proper database)
    private HashMap<String, String> userDatabase = new HashMap<>();

    public SecureChatServer() {
        // Initialize simple user database
        initializeUserDatabase();
    }

    private void initializeUserDatabase() {
        // Hash passwords using SHA-256
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
            return password; // Fallback (not secure)
        }
    }

    /**
     * Start the server
     */
    public void startServer() {
        try {
            serverSocket = new ServerSocket(PORT);
            isRunning = true;
            System.out.println("🚀 Secure Chat Server started on port " + PORT);
            System.out.println("📋 Available users: " + userDatabase.keySet());
            System.out.println("🔐 Encryption: AES-128");
            System.out.println("Waiting for clients to connect...\n");

            while (isRunning) {
                try {
                    Socket clientSocket = serverSocket.accept();
                    System.out.println("📥 New connection attempt from: " +
                            clientSocket.getInetAddress().getHostAddress());

                    // Handle each client in a separate thread
                    ClientHandler clientHandler = new ClientHandler(clientSocket);
                    clientThreadPool.submit(clientHandler);

                } catch (IOException e) {
                    if (isRunning) {
                        System.err.println("Error accepting client connection: " + e.getMessage());
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
     * Broadcast message to all authenticated clients except sender
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
     * Send private message to specific user
     */
    private void sendPrivateMessage(String message, String targetUsername, String senderUsername) {
        ClientHandler targetClient = clients.get(targetUsername);
        if (targetClient != null) {
            targetClient.sendMessage("[PRIVATE from " + senderUsername + "]: " + message);
            // Send confirmation to sender
            ClientHandler senderClient = clients.get(senderUsername);
            if (senderClient != null) {
                senderClient.sendMessage("[PRIVATE to " + targetUsername + "]: " + message);
            }
        } else {
            ClientHandler senderClient = clients.get(senderUsername);
            if (senderClient != null) {
                senderClient.sendMessage("❌ User '" + targetUsername + "' not found or offline.");
            }
        }
    }

    /**
     * Client handler class for managing individual client connections
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

        /**
         * Setup AES encryption
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
                return message; // Return original if encryption fails
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
                return encryptedMessage; // Return original if decryption fails
            }
        }

        @Override
        public void run() {
            try {
                input = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                output = new PrintWriter(clientSocket.getOutputStream(), true);

                // Send welcome message
                sendMessage("🔐 Welcome to Secure Chat Server!");
                sendMessage("Please authenticate to continue.");

                // Authentication process
                if (authenticate()) {
                    sendMessage("✅ Authentication successful! Welcome " + username + "!");
                    sendMessage("📝 Commands: /list (show users), /private <user> <message>, /quit");
                    sendMessage("🔐 All messages are encrypted with AES-128");

                    // Notify other users
                    broadcastMessage("📢 " + username + " joined the chat!", username);

                    // Listen for messages
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
                            // Broadcast public message
                            String chatMessage = "💬 " + username + ": " + message;
                            System.out.println("[" + new Date() + "] " + chatMessage);
                            broadcastMessage(chatMessage, username);
                        }
                    }
                }

            } catch (IOException e) {
                System.err.println("Error handling client " + username + ": " + e.getMessage());
            } finally {
                cleanup();
            }
        }

        /**
         * Handle authentication
         */
        private boolean authenticate() {
            try {
                sendMessage("Username: ");
                String inputUsername = decrypt(input.readLine());

                sendMessage("Password: ");
                String inputPassword = decrypt(input.readLine());

                String hashedInput = hashPassword(inputPassword);

                if (userDatabase.containsKey(inputUsername) &&
                        userDatabase.get(inputUsername).equals(hashedInput)) {

                    // Check if user already logged in
                    if (clients.containsKey(inputUsername)) {
                        sendMessage("❌ User already logged in!");
                        return false;
                    }

                    this.username = inputUsername;
                    this.isAuthenticated = true;
                    clients.put(username, this);
                    authenticatedUsers.put(username, clientSocket.getInetAddress().getHostAddress());

                    System.out.println("✅ User '" + username + "' authenticated successfully");
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

        /**
         * Handle private messages
         */
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

        /**
         * Send encrypted message to client
         */
        public void sendMessage(String message) {
            if (output != null) {
                String encryptedMessage = encrypt(message);
                output.println(encryptedMessage);
            }
        }

        /**
         * Cleanup when client disconnects
         */
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
                System.err.println("Error cleaning up client connection: " + e.getMessage());
            }
        }
    }

    /**
     * Main method to start the server
     */
    public static void main(String[] args) {
        SecureChatServer server = new SecureChatServer();

        // Handle graceful shutdown
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("\n🛑 Shutting down server...");
            server.stopServer();
        }));

        server.startServer();
    }
}