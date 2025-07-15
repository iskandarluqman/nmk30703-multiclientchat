package org.nmk30703.minip;

import java.io.*;
import java.net.*;
import java.util.Scanner;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Base64;

/**
 * Secure Chat Client
 * Connects to the secure chat server with encryption
 * Course: NMK30703 Programming for Networking
 */
public class SecureChatClient {
    private static final String SERVER_HOST = "localhost";
    private static final int SERVER_PORT = 12345;
    private static final String SECRET_KEY = "MySecretKey12345"; // Must match server

    private Socket socket;
    private BufferedReader input;
    private PrintWriter output;
    private Scanner scanner;
    private boolean isConnected = false;
    private Cipher encryptCipher;
    private Cipher decryptCipher;
    private String username;

    public SecureChatClient() {
        scanner = new Scanner(System.in);
        setupEncryption();
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
     * Connect to the server
     */
    public void connectToServer() {
        try {
            System.out.println("🔗 Connecting to Secure Chat Server...");
            socket = new Socket(SERVER_HOST, SERVER_PORT);
            input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            output = new PrintWriter(socket.getOutputStream(), true);
            isConnected = true;

            System.out.println("✅ Connected to server: " + SERVER_HOST + ":" + SERVER_PORT);

            // Start thread to listen for server messages
            Thread serverListener = new Thread(this::listenForServerMessages);
            serverListener.setDaemon(true);
            serverListener.start();

            // Handle authentication
            authenticate();

            // Start sending messages
            sendMessages();

        } catch (IOException e) {
            System.err.println("❌ Error connecting to server: " + e.getMessage());
            System.err.println("Make sure the server is running on " + SERVER_HOST + ":" + SERVER_PORT);
        }
    }

    /**
     * Handle authentication with server
     */
    private void authenticate() {
        try {
            // Wait for server prompts and respond
            Thread.sleep(500); // Give server time to send welcome messages

            // System.out.print("Enter username: ");
            username = scanner.nextLine();
            sendEncryptedMessage(username);

            //System.out.print("Enter password: ");
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
            }
        }
    }

    /**
     * Send messages to server
     */
    private void sendMessages() {
        System.out.println("\n📝 You can start chatting! Type '/help' for commands or '/quit' to exit.");

        String message;
        while (isConnected && (message = scanner.nextLine()) != null) {
            if (message.equals("/quit")) {
                sendEncryptedMessage(message);
                break;
            } else if (message.equals("/help")) {
                showHelp();
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
        System.out.println("  /quit                    - Exit chat");
        System.out.println("  /help                    - Show this help");
        System.out.println("  <message>                - Send public message\n");
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
     * Main method to start the client
     */
    public static void main(String[] args) {
        System.out.println("🔐 Secure Chat Client");
        System.out.println("========================");
        System.out.println("Available test accounts:");
        System.out.println("  Username: admin,  Password: admin123");
        System.out.println("  Username: user1,  Password: password1");
        System.out.println("  Username: user2,  Password: password2");
        System.out.println("  Username: guest,  Password: guest123");
        System.out.println("========================\n");

        SecureChatClient client = new SecureChatClient();

        // Handle graceful shutdown
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("\n🛑 Client shutting down...");
            client.disconnect();
        }));

        client.connectToServer();
    }
}
