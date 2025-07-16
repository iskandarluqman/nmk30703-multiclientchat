package org.nmk30703.minip;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Base64;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Enumeration;

/**
 * Secure Chat Client with GUI
 * User-friendly graphical interface for the secure chat application
 * Now supports connecting to servers on different IP addresses with auto-detection
 */
public class SecureChatClientGUI extends JFrame {
    private static final String DEFAULT_SERVER_HOST = "localhost";
    private static final int DEFAULT_SERVER_PORT = 30703;
    private static final String SECRET_KEY = "UniMAPMantap2025";

    // GUI Components
    private JTextArea chatArea;
    private JTextField messageField;
    private JButton sendButton;
    private JButton connectButton;
    private JButton disconnectButton;
    private JLabel statusLabel;
    private JTextField usernameField;
    private JPasswordField passwordField;
    private JTextField serverHostField;
    private JTextField serverPortField;
    private JPanel loginPanel;
    private JPanel chatPanel;
    private JButton testConnectionButton;
    private JButton detectIPButton;

    // Networking components
    private Socket socket;
    private BufferedReader input;
    private PrintWriter output;
    private boolean isConnected = false;
    private boolean isAuthenticating = false;
    private Cipher encryptCipher;
    private Cipher decryptCipher;
    private String username;
    private String serverHost = DEFAULT_SERVER_HOST;
    private int serverPort = DEFAULT_SERVER_PORT;
    private String detectedIP = DEFAULT_SERVER_HOST;
    private String pendingUsername = "";
    private String pendingPassword = "";

    public SecureChatClientGUI() {
        setupEncryption();
        detectNetworkIP();
        initializeGUI();
    }

    /**
     * Detect network IP using InetAddress (following lecture material)
     */
    private void detectNetworkIP() {
        try {
            System.out.println("Detecting network IP using InetAddress class...");

            // Primary method: Use InetAddress.getLocalHost() as taught in lecture
            InetAddress localhost = InetAddress.getLocalHost();
            System.out.println("Localhost: " + localhost);
            System.out.println("Localhost IP: " + localhost.getHostAddress());
            System.out.println("Localhost hostname: " + localhost.getHostName());

            String localhostIP = localhost.getHostAddress();

            // If localhost gives us a useful IP, use it
            if (localhostIP != null && !localhostIP.equals("127.0.0.1")) {
                detectedIP = localhostIP;
                System.out.println("Using localhost IP: " + detectedIP);
            } else {
                // Fallback: scan network interfaces for private IPs
                detectedIP = scanNetworkInterfaces();
            }

            System.out.println("Final detected IP: " + detectedIP);

        } catch (Exception e) {
            System.err.println("Error detecting network IP: " + e.getMessage());
            detectedIP = DEFAULT_SERVER_HOST;
        }
    }

    /**
     * Scan network interfaces for private IP addresses
     */
    private String scanNetworkInterfaces() {
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();

            while (interfaces.hasMoreElements()) {
                NetworkInterface ni = interfaces.nextElement();

                if (ni.isUp() && !ni.isLoopback()) {
                    Enumeration<InetAddress> addresses = ni.getInetAddresses();
                    while (addresses.hasMoreElements()) {
                        InetAddress addr = addresses.nextElement();

                        if (addr instanceof Inet4Address) {
                            String ip = addr.getHostAddress();
                            // Prefer private network IPs
                            if (ip.startsWith("192.168.") || ip.startsWith("10.") ||
                                    (ip.startsWith("172.") && ip.split("\\.")[1].matches("(1[6-9]|2[0-9]|3[01])"))) {
                                System.out.println("Found private network IP: " + ip);
                                return ip;
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Error scanning network interfaces: " + e.getMessage());
        }

        return DEFAULT_SERVER_HOST;
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
            JOptionPane.showMessageDialog(this, "Error setting up encryption: " + e.getMessage(),
                    "Encryption Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    /**
     * Initialize the GUI components
     */
    private void initializeGUI() {
        setTitle("Secure Chat Client - Multi-PC Support");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(650, 550);
        setLocationRelativeTo(null);

        // Create login panel
        createLoginPanel();

        // Create chat panel
        createChatPanel();

        // Initially show login panel
        add(loginPanel);

        // Add window listener for cleanup
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                disconnect();
                System.exit(0);
            }
        });

        // Add shutdown hook for proper cleanup
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            disconnect();
        }));
    }

    /**
     * Create login panel
     */
    private void createLoginPanel() {
        loginPanel = new JPanel(new GridBagLayout());
        loginPanel.setBorder(new EmptyBorder(20, 20, 20, 20));
        GridBagConstraints gbc = new GridBagConstraints();

        // Title
        JLabel titleLabel = new JLabel("Secure Chat Login", SwingConstants.CENTER);
        titleLabel.setFont(new Font("Arial", Font.BOLD, 18));
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 2;
        gbc.insets = new Insets(0, 0, 20, 0);
        loginPanel.add(titleLabel, gbc);

        // Server configuration section
        JLabel serverConfigLabel = new JLabel("Server Configuration", SwingConstants.CENTER);
        serverConfigLabel.setFont(new Font("Arial", Font.BOLD, 14));
        gbc.gridy = 1; gbc.insets = new Insets(0, 0, 10, 0);
        loginPanel.add(serverConfigLabel, gbc);

        // Server host
        gbc.gridwidth = 1; gbc.insets = new Insets(5, 5, 5, 5);
        gbc.gridy = 2; gbc.gridx = 0; gbc.anchor = GridBagConstraints.EAST;
        loginPanel.add(new JLabel("Server Host:"), gbc);

        serverHostField = new JTextField(detectedIP, 25);
        serverHostField.setPreferredSize(new Dimension(250, 25));
        gbc.gridx = 1; gbc.anchor = GridBagConstraints.WEST; gbc.fill = GridBagConstraints.HORIZONTAL;
        loginPanel.add(serverHostField, gbc);

        // Server port
        gbc.gridy = 3; gbc.gridx = 0; gbc.anchor = GridBagConstraints.EAST; gbc.fill = GridBagConstraints.NONE;
        loginPanel.add(new JLabel("Server Port:"), gbc);

        serverPortField = new JTextField(String.valueOf(DEFAULT_SERVER_PORT), 25);
        serverPortField.setPreferredSize(new Dimension(250, 25));
        gbc.gridx = 1; gbc.anchor = GridBagConstraints.WEST; gbc.fill = GridBagConstraints.HORIZONTAL;
        loginPanel.add(serverPortField, gbc);

        // Detect IP and Test connection buttons
        JPanel buttonPanel = new JPanel(new FlowLayout());
        detectIPButton = new JButton("Detect IP");
        detectIPButton.addActionListener(e -> {
            detectNetworkIP();
            serverHostField.setText(detectedIP);
            JOptionPane.showMessageDialog(this, "Network IP detected: " + detectedIP,
                    "IP Detection", JOptionPane.INFORMATION_MESSAGE);
        });

        testConnectionButton = new JButton("Test Connection");
        testConnectionButton.addActionListener(e -> testConnection());

        buttonPanel.add(detectIPButton);
        buttonPanel.add(testConnectionButton);

        gbc.gridy = 4; gbc.gridx = 0; gbc.gridwidth = 2; gbc.anchor = GridBagConstraints.CENTER; gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(10, 5, 10, 5);
        loginPanel.add(buttonPanel, gbc);

        // User authentication section
        JLabel authLabel = new JLabel("User Authentication", SwingConstants.CENTER);
        authLabel.setFont(new Font("Arial", Font.BOLD, 14));
        gbc.gridy = 5; gbc.insets = new Insets(20, 0, 10, 0);
        loginPanel.add(authLabel, gbc);

        // Test accounts info
        JTextArea accountsInfo = new JTextArea(
                "Test Accounts:\n" +
                        "admin / admin123\n" +
                        "user1 / password1\n" +
                        "user2 / password2\n" +
                        "guest / guest123"
        );
        accountsInfo.setEditable(false);
        accountsInfo.setBackground(loginPanel.getBackground());
        accountsInfo.setFont(new Font("Monospaced", Font.PLAIN, 11));
        gbc.gridy = 6; gbc.insets = new Insets(0, 0, 20, 0);
        loginPanel.add(accountsInfo, gbc);

        // Username
        gbc.gridwidth = 1; gbc.insets = new Insets(5, 5, 5, 5);
        gbc.gridy = 7; gbc.gridx = 0; gbc.anchor = GridBagConstraints.EAST;
        loginPanel.add(new JLabel("Username:"), gbc);

        usernameField = new JTextField(25);
        usernameField.setPreferredSize(new Dimension(250, 25));
        gbc.gridx = 1; gbc.anchor = GridBagConstraints.WEST; gbc.fill = GridBagConstraints.HORIZONTAL;
        loginPanel.add(usernameField, gbc);

        // Password
        gbc.gridy = 8; gbc.gridx = 0; gbc.anchor = GridBagConstraints.EAST; gbc.fill = GridBagConstraints.NONE;
        loginPanel.add(new JLabel("Password:"), gbc);

        passwordField = new JPasswordField(25);
        passwordField.setPreferredSize(new Dimension(250, 25));
        gbc.gridx = 1; gbc.anchor = GridBagConstraints.WEST; gbc.fill = GridBagConstraints.HORIZONTAL;
        loginPanel.add(passwordField, gbc);

        // Connect button
        connectButton = new JButton("Connect to Server");
        connectButton.addActionListener(e -> connectToServer());
        gbc.gridy = 9; gbc.gridx = 0; gbc.gridwidth = 2; gbc.anchor = GridBagConstraints.CENTER; gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(20, 5, 5, 5);
        loginPanel.add(connectButton, gbc);

        // Status label
        statusLabel = new JLabel("Ready to connect", SwingConstants.CENTER);
        statusLabel.setForeground(Color.BLUE);
        gbc.gridy = 10; gbc.insets = new Insets(10, 5, 5, 5);
        loginPanel.add(statusLabel, gbc);

        // Network info label
        JLabel networkInfo = new JLabel("Detected network IP: " + detectedIP, SwingConstants.CENTER);
        networkInfo.setFont(new Font("Arial", Font.ITALIC, 11));
        networkInfo.setForeground(Color.GRAY);
        gbc.gridy = 11; gbc.insets = new Insets(5, 5, 5, 5);
        loginPanel.add(networkInfo, gbc);

        // Enter key listeners
        serverHostField.addActionListener(e -> serverPortField.requestFocus());
        serverPortField.addActionListener(e -> usernameField.requestFocus());
        usernameField.addActionListener(e -> passwordField.requestFocus());
        passwordField.addActionListener(e -> connectToServer());
    }

    /**
     * Test connection to server
     */
    private void testConnection() {
        updateServerSettings();

        testConnectionButton.setEnabled(false);
        statusLabel.setText("Testing connection...");
        statusLabel.setForeground(Color.ORANGE);

        new Thread(() -> {
            try {
                Socket testSocket = new Socket();
                testSocket.connect(new InetSocketAddress(serverHost, serverPort), 5000);
                testSocket.close();

                SwingUtilities.invokeLater(() -> {
                    statusLabel.setText("Connection successful!");
                    statusLabel.setForeground(Color.GREEN);
                    testConnectionButton.setEnabled(true);
                });
            } catch (IOException e) {
                SwingUtilities.invokeLater(() -> {
                    statusLabel.setText("Connection failed: " + e.getMessage());
                    statusLabel.setForeground(Color.RED);
                    testConnectionButton.setEnabled(true);

                    // Show detailed error message
                    String errorMsg = "Connection failed to " + serverHost + ":" + serverPort + "\n\n" +
                            "Possible causes:\n" +
                            "• Server is not running\n" +
                            "• Incorrect IP address or port\n" +
                            "• Firewall blocking connection\n" +
                            "• Network connectivity issues\n\n" +
                            "Error: " + e.getMessage();

                    JOptionPane.showMessageDialog(SecureChatClientGUI.this, errorMsg,
                            "Connection Test Failed", JOptionPane.ERROR_MESSAGE);
                });
            }
        }).start();
    }

    /**
     * Update server settings from input fields
     */
    private void updateServerSettings() {
        serverHost = serverHostField.getText().trim();
        if (serverHost.isEmpty()) {
            serverHost = detectedIP;
            serverHostField.setText(serverHost);
        }

        try {
            serverPort = Integer.parseInt(serverPortField.getText().trim());
        } catch (NumberFormatException e) {
            serverPort = DEFAULT_SERVER_PORT;
            serverPortField.setText(String.valueOf(serverPort));
            JOptionPane.showMessageDialog(this, "Invalid port number. Using default: " + DEFAULT_SERVER_PORT,
                    "Invalid Port", JOptionPane.WARNING_MESSAGE);
        }
    }

    /**
     * Create chat panel
     */
    private void createChatPanel() {
        chatPanel = new JPanel(new BorderLayout());
        chatPanel.setBorder(new EmptyBorder(10, 10, 10, 10));

        // Chat area
        chatArea = new JTextArea();
        chatArea.setEditable(false);
        chatArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        chatArea.setBackground(Color.WHITE);
        JScrollPane scrollPane = new JScrollPane(chatArea);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        chatPanel.add(scrollPane, BorderLayout.CENTER);

        // Message input panel
        JPanel inputPanel = new JPanel(new BorderLayout());
        inputPanel.setBorder(new EmptyBorder(10, 0, 0, 0));

        messageField = new JTextField();
        messageField.addActionListener(e -> sendMessage());
        inputPanel.add(messageField, BorderLayout.CENTER);

        sendButton = new JButton("Send");
        sendButton.addActionListener(e -> sendMessage());
        inputPanel.add(sendButton, BorderLayout.EAST);

        chatPanel.add(inputPanel, BorderLayout.SOUTH);

        // Top panel with server info and controls
        JPanel topPanel = new JPanel(new BorderLayout());
        JLabel serverInfoLabel = new JLabel("Server: ");

        JPanel buttonPanel = new JPanel(new FlowLayout());

        JButton infoButton = new JButton("Info");
        infoButton.addActionListener(e -> showConnectionInfo());

        JButton helpButton = new JButton("Help");
        helpButton.addActionListener(e -> showHelp());

        disconnectButton = new JButton("Disconnect");
        disconnectButton.addActionListener(e -> disconnect());

        buttonPanel.add(infoButton);
        buttonPanel.add(helpButton);
        buttonPanel.add(disconnectButton);

        topPanel.add(serverInfoLabel, BorderLayout.WEST);
        topPanel.add(buttonPanel, BorderLayout.EAST);
        chatPanel.add(topPanel, BorderLayout.NORTH);
    }

    /**
     * Show connection information
     */
    private void showConnectionInfo() {
        String info = "Connection Information\n\n" +
                "Server: " + serverHost + ":" + serverPort + "\n" +
                "Username: " + username + "\n" +
                "Encryption: AES-128\n" +
                "Status: " + (isConnected ? "Connected" : "Disconnected");

        if (isConnected && socket != null) {
            info += "\nLocal Address: " + socket.getLocalAddress().getHostAddress() + ":" + socket.getLocalPort();
        }

        JOptionPane.showMessageDialog(this, info, "Connection Info", JOptionPane.INFORMATION_MESSAGE);
    }

    /**
     * Connect to server
     */
    private void connectToServer() {
        updateServerSettings();

        String user = usernameField.getText().trim();
        String pass = new String(passwordField.getPassword());

        if (user.isEmpty() || pass.isEmpty()) {
            statusLabel.setText("Please enter username and password");
            statusLabel.setForeground(Color.RED);
            return;
        }

        // Store credentials for authentication
        pendingUsername = user;
        pendingPassword = pass;

        connectButton.setEnabled(false);
        testConnectionButton.setEnabled(false);
        detectIPButton.setEnabled(false);
        statusLabel.setText("Connecting to " + serverHost + ":" + serverPort + "...");
        statusLabel.setForeground(Color.ORANGE);

        // Connect in background thread
        new Thread(() -> {
            try {
                socket = new Socket(serverHost, serverPort);
                input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                output = new PrintWriter(socket.getOutputStream(), true);
                isAuthenticating = true;

                SwingUtilities.invokeLater(() -> {
                    statusLabel.setText("Authenticating...");
                });

                // Start server listener
                Thread serverListener = new Thread(this::listenForServerMessages);
                serverListener.setDaemon(true);
                serverListener.start();

                // Wait for authentication to complete (handled in message listener)
                int timeout = 0;
                while (isAuthenticating && timeout < 60) { // 30 second timeout
                    Thread.sleep(500);
                    timeout++;
                }

                if (isConnected) {
                    username = pendingUsername;
                    SwingUtilities.invokeLater(() -> {
                        remove(loginPanel);
                        add(chatPanel);
                        validate();
                        repaint();

                        // Clear chat area from previous sessions
                        if (chatArea != null) {
                            chatArea.setText("");
                            chatArea.append("=== Connected to " + serverHost + ":" + serverPort + " ===\n");
                            chatArea.append("Welcome " + username + "!\n\n");
                        }

                        messageField.requestFocus();

                        // Update server info label
                        Component[] components = ((JPanel)chatPanel.getComponent(2)).getComponents();
                        if (components[0] instanceof JLabel) {
                            ((JLabel)components[0]).setText("Server: " + serverHost + ":" + serverPort + " | User: " + username);
                        }

                        // Automatically send /list command to show online users
                        new Thread(() -> {
                            try {
                                Thread.sleep(1000); // Wait a moment for connection to stabilize
                                sendEncryptedMessage("/list");
                                System.out.println("Automatically sent /list command");
                            } catch (InterruptedException e) {
                                System.err.println("Error sending auto /list command: " + e.getMessage());
                            }
                        }).start();
                    });
                } else {
                    SwingUtilities.invokeLater(() -> {
                        if (isAuthenticating) {
                            statusLabel.setText("Authentication timeout");
                        } else {
                            statusLabel.setText("Authentication failed - Check credentials");
                        }
                        statusLabel.setForeground(Color.RED);
                        connectButton.setEnabled(true);
                        testConnectionButton.setEnabled(true);
                        detectIPButton.setEnabled(true);
                    });
                    // Close connection on failed authentication
                    try {
                        if (socket != null && !socket.isClosed()) {
                            socket.close();
                        }
                    } catch (IOException ex) {
                        System.err.println("Error closing socket: " + ex.getMessage());
                    }
                }

            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> {
                    statusLabel.setText("Connection failed: " + e.getMessage());
                    statusLabel.setForeground(Color.RED);
                    connectButton.setEnabled(true);
                    testConnectionButton.setEnabled(true);
                    detectIPButton.setEnabled(true);

                    // Show detailed error
                    String errorMsg = "Failed to connect to " + serverHost + ":" + serverPort + "\n\n" +
                            "Error: " + e.getMessage() + "\n\n" +
                            "Please check:\n" +
                            "• Server is running\n" +
                            "• Correct IP address and port\n" +
                            "• Network connectivity\n" +
                            "• Firewall settings";

                    JOptionPane.showMessageDialog(SecureChatClientGUI.this, errorMsg,
                            "Connection Failed", JOptionPane.ERROR_MESSAGE);
                });
                isAuthenticating = false;
            }
        }).start();
    }

    /**
     * Listen for server messages
     */
    private void listenForServerMessages() {
        try {
            String encryptedMessage;
            while ((encryptedMessage = input.readLine()) != null) {
                if (encryptedMessage.trim().isEmpty()) {
                    continue; // Skip empty messages
                }

                String message = decrypt(encryptedMessage);
                if (message == null || message.isEmpty()) {
                    continue; // Skip if decryption failed
                }

                System.out.println("Received from server: " + message);

                // Handle authentication flow
                if (isAuthenticating) {
                    if (message.contains("Username:") || message.endsWith("Username: ")) {
                        System.out.println("Sending username: " + pendingUsername);
                        sendEncryptedMessage(pendingUsername);
                        continue;
                    } else if (message.contains("Password:") || message.endsWith("Password: ")) {
                        System.out.println("Sending password");
                        sendEncryptedMessage(pendingPassword);
                        continue;
                    } else if (message.contains("Authentication successful") ||
                            message.contains("Welcome " + pendingUsername)) {
                        isConnected = true;
                        isAuthenticating = false;
                        System.out.println("Authentication successful!");
                        continue;
                    } else if (message.contains("Invalid credentials") ||
                            message.contains("already logged") ||
                            message.contains("User already")) {
                        isConnected = false;
                        isAuthenticating = false;
                        System.out.println("Authentication failed!");
                        continue;
                    } else if (message.contains("Welcome to") ||
                            message.contains("Please authenticate") ||
                            message.contains("Commands:")) {
                        // Skip welcome and instruction messages during authentication
                        continue;
                    }
                }

                // Handle chat messages (only when connected and not authenticating)
                if (isConnected && !isAuthenticating) {
                    SwingUtilities.invokeLater(() -> {
                        if (chatArea != null) {
                            // Add timestamp and display message
                            String timestamp = new SimpleDateFormat("HH:mm:ss").format(new Date());

                            // Special formatting for /list command response
                            if (message.contains("Online users:")) {
                                chatArea.append("[" + timestamp + "] " + message + "\n");
                                chatArea.append("Type your message below to chat with everyone!\n\n");
                            } else {
                                chatArea.append("[" + timestamp + "] " + message + "\n");
                            }

                            chatArea.setCaretPosition(chatArea.getDocument().getLength());
                        }
                    });
                }
            }
        } catch (IOException e) {
            System.out.println("Connection closed: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("Error in message listener: " + e.getMessage());
        } finally {
            isAuthenticating = false;
            if (isConnected) {
                SwingUtilities.invokeLater(() -> {
                    if (chatArea != null) {
                        chatArea.append("\nConnection lost.\n");
                        chatArea.setCaretPosition(chatArea.getDocument().getLength());
                    }
                });
            }
        }
    }

    /**
     * Send message
     */
    private void sendMessage() {
        String message = messageField.getText().trim();
        if (!message.isEmpty() && isConnected) {
            if (message.equals("/quit")) {
                disconnect();
                return;
            }

            // Display your own message in chat area immediately
            String timestamp = new SimpleDateFormat("HH:mm:ss").format(new Date());
            if (message.startsWith("/")) {
                // For commands, show what you typed
                chatArea.append("[" + timestamp + "] You: " + message + "\n");
            } else {
                // For regular messages, show as sent
                chatArea.append("[" + timestamp + "] " + username + ": " + message + "\n");
            }
            chatArea.setCaretPosition(chatArea.getDocument().getLength());

            sendEncryptedMessage(message);
            messageField.setText("");
            messageField.requestFocus();
        }
    }

    /**
     * Show help dialog
     */
    private void showHelp() {
        String helpText = "Available Commands:\n\n" +
                "/list - Show online users\n" +
                "/private <user> <message> - Send private message\n" +
                "/info - Show connection info\n" +
                "/quit - Exit chat\n\n" +
                "Tips:\n" +
                "• All messages are encrypted with AES-128\n" +
                "• Press Enter to send messages\n" +
                "• Private messages are shown in chat area\n" +
                "• Use /list to see who's online\n" +
                "• Test connection before connecting\n\n" +
                "Multi-PC Support:\n" +
                "• Enter server IP address in login screen\n" +
                "• Default port is 30703\n" +
                "• Use Test Connection to verify connectivity";

        JOptionPane.showMessageDialog(this, helpText, "Help", JOptionPane.INFORMATION_MESSAGE);
    }

    /**
     * Encrypt and send message
     */
    private void sendEncryptedMessage(String message) {
        if (output != null && !socket.isClosed()) {
            try {
                String encryptedMessage = encrypt(message);
                output.println(encryptedMessage);
                output.flush(); // Ensure message is sent immediately
                System.out.println("Sent to server: " + message);
            } catch (Exception e) {
                System.err.println("Error sending message: " + e.getMessage());
            }
        }
    }

    /**
     * Encrypt message
     */
    private String encrypt(String message) {
        try {
            if (message == null || message.isEmpty()) {
                return "";
            }
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
            if (encryptedMessage == null || encryptedMessage.isEmpty()) {
                return "";
            }
            byte[] decoded = Base64.getDecoder().decode(encryptedMessage);
            byte[] decrypted = decryptCipher.doFinal(decoded);
            return new String(decrypted);
        } catch (Exception e) {
            System.err.println("Error decrypting message: " + e.getMessage());
            return encryptedMessage != null ? encryptedMessage : "";
        }
    }

    /**
     * Disconnect from server
     */
    private void disconnect() {
        System.out.println("Disconnecting from server...");

        // Stop authentication process
        isAuthenticating = false;

        if (isConnected) {
            try {
                sendEncryptedMessage("/quit");
            } catch (Exception e) {
                System.out.println("Error sending quit message: " + e.getMessage());
            }
        }

        isConnected = false;

        // Close connections
        try {
            if (input != null) {
                input.close();
                input = null;
            }
            if (output != null) {
                output.close();
                output = null;
            }
            if (socket != null && !socket.isClosed()) {
                socket.close();
                socket = null;
            }
        } catch (IOException e) {
            System.out.println("Error during cleanup: " + e.getMessage());
        }

        SwingUtilities.invokeLater(() -> {
            if (chatPanel.getParent() != null) {
                remove(chatPanel);
                add(loginPanel);
                validate();
                repaint();
            }

            // Re-enable buttons
            connectButton.setEnabled(true);
            testConnectionButton.setEnabled(true);
            detectIPButton.setEnabled(true);

            // Update status
            statusLabel.setText("Disconnected from " + serverHost + ":" + serverPort);
            statusLabel.setForeground(Color.BLUE);

            // Clear credentials and reset chat area
            usernameField.setText("");
            passwordField.setText("");
            pendingUsername = "";
            pendingPassword = "";

            // Clear chat area for next session
            if (chatArea != null) {
                chatArea.setText("");
            }
        });

        System.out.println("Disconnect completed.");
    }

    /**
     * Main method
     */
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            new SecureChatClientGUI().setVisible(true);
        });
    }
}