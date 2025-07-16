package org.nmk30703.minip;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.*;
import java.util.Enumeration;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Base64;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * Secure Chat Client with GUI
 * User-friendly graphical interface for the secure chat application
 * Now supports connecting to servers on different IP addresses
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

    // Networking components
    private Socket socket;
    private BufferedReader input;
    private PrintWriter output;
    private boolean isConnected = false;
    private Cipher encryptCipher;
    private Cipher decryptCipher;
    private String username;
    private String serverHost = DEFAULT_SERVER_HOST;
    private int serverPort = DEFAULT_SERVER_PORT;
    private String detectedNetworkIP;

    public SecureChatClientGUI() {
        detectNetworkIP(); // Detect network IP first
        setupEncryption();
        initializeGUI();
    }

    /**
     * Detect the network IP address to use as default server
     * Using InetAddress class as per NMK30703 lab module
     */
    private void detectNetworkIP() {
        try {
            System.out.println("Detecting network IP using InetAddress class...");

            // Method 1: Get localhost address (as per lecture)
            InetAddress localhost = InetAddress.getLocalHost();
            System.out.println("Localhost: " + localhost);
            System.out.println("Localhost IP: " + localhost.getHostAddress());
            System.out.println("Localhost hostname: " + localhost.getHostName());

            // Check if localhost gives us a proper network IP
            String localhostIP = localhost.getHostAddress();
            if (!localhostIP.equals("127.0.0.1") && !localhostIP.equals("localhost")) {
                detectedNetworkIP = localhostIP;
                serverHost = localhostIP;
                System.out.println("✅ Using localhost IP: " + localhostIP);
                return;
            }

            // Method 2: Scan network interfaces for better IP detection
            System.out.println("Localhost returned loopback, scanning network interfaces...");
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface ni = interfaces.nextElement();
                System.out.println("Interface: " + ni.getDisplayName() + " - Up: " + ni.isUp() + " - Loopback: " + ni.isLoopback());

                if (ni.isUp() && !ni.isLoopback() && !ni.isVirtual()) {
                    Enumeration<InetAddress> addresses = ni.getInetAddresses();
                    while (addresses.hasMoreElements()) {
                        InetAddress addr = addresses.nextElement();
                        System.out.println("  Address: " + addr.getHostAddress() + " - IPv4: " + (addr instanceof Inet4Address));

                        if (addr instanceof Inet4Address && !addr.isLoopbackAddress()) {
                            String ip = addr.getHostAddress();
                            System.out.println("  Checking IP: " + ip);

                            // Prefer private network addresses (as per networking fundamentals)
                            if (ip.startsWith("192.168.") || ip.startsWith("10.") ||
                                    ip.startsWith("172.16.") || ip.startsWith("172.17.") ||
                                    ip.startsWith("172.18.") || ip.startsWith("172.19.") ||
                                    ip.startsWith("172.20.") || ip.startsWith("172.21.") ||
                                    ip.startsWith("172.22.") || ip.startsWith("172.23.") ||
                                    ip.startsWith("172.24.") || ip.startsWith("172.25.") ||
                                    ip.startsWith("172.26.") || ip.startsWith("172.27.") ||
                                    ip.startsWith("172.28.") || ip.startsWith("172.29.") ||
                                    ip.startsWith("172.30.") || ip.startsWith("172.31.")) {
                                detectedNetworkIP = ip;
                                serverHost = ip;
                                System.out.println("✅ Selected private network IP: " + ip);
                                return;
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Error detecting network IP: " + e.getMessage());
            e.printStackTrace();
        }

        // Final fallback to localhost
        if (detectedNetworkIP == null) {
            System.out.println("❌ No suitable network IP found, using localhost");
            detectedNetworkIP = "localhost";
            serverHost = "localhost";
        }

        System.out.println("Final detected IP: " + detectedNetworkIP);
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
        setTitle("🔐 Secure Chat Client - Multi-PC Support");
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
    }

    /**
     * Create login panel
     */
    private void createLoginPanel() {
        loginPanel = new JPanel(new GridBagLayout());
        loginPanel.setBorder(new EmptyBorder(20, 20, 20, 20));
        GridBagConstraints gbc = new GridBagConstraints();

        // Title
        JLabel titleLabel = new JLabel("🔐 Secure Chat Login", SwingConstants.CENTER);
        titleLabel.setFont(new Font("Arial", Font.BOLD, 18));
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 2;
        gbc.insets = new Insets(0, 0, 20, 0);
        loginPanel.add(titleLabel, gbc);

        // Server configuration section
        JLabel serverConfigLabel = new JLabel("🌐 Server Configuration", SwingConstants.CENTER);
        serverConfigLabel.setFont(new Font("Arial", Font.BOLD, 14));
        gbc.gridy = 1; gbc.insets = new Insets(0, 0, 10, 0);
        loginPanel.add(serverConfigLabel, gbc);

        // Server host
        gbc.gridwidth = 1; gbc.insets = new Insets(5, 5, 5, 5);
        gbc.gridy = 2; gbc.gridx = 0; gbc.anchor = GridBagConstraints.EAST;
        loginPanel.add(new JLabel("Server Host:"), gbc);

        serverHostField = new JTextField(serverHost != null ? serverHost : DEFAULT_SERVER_HOST, 20);
        serverHostField.setToolTipText("Detected network IP: " + (detectedNetworkIP != null ? detectedNetworkIP : "Not detected"));
        serverHostField.setPreferredSize(new Dimension(200, 25));
        gbc.gridx = 1; gbc.anchor = GridBagConstraints.WEST; gbc.fill = GridBagConstraints.HORIZONTAL;
        loginPanel.add(serverHostField, gbc);

        // Network detection button
        JButton detectButton = new JButton("🔍 Detect");
        detectButton.setToolTipText("Auto-detect network IP");
        detectButton.addActionListener(e -> autoDetectNetwork());
        gbc.gridx = 2; gbc.anchor = GridBagConstraints.WEST; gbc.fill = GridBagConstraints.NONE;
        loginPanel.add(detectButton, gbc);

        // Server port
        gbc.gridy = 3; gbc.gridx = 0; gbc.anchor = GridBagConstraints.EAST;
        loginPanel.add(new JLabel("Server Port:"), gbc);

        serverPortField = new JTextField(String.valueOf(DEFAULT_SERVER_PORT), 20);
        serverPortField.setPreferredSize(new Dimension(200, 25));
        gbc.gridx = 1; gbc.anchor = GridBagConstraints.WEST; gbc.fill = GridBagConstraints.HORIZONTAL;
        loginPanel.add(serverPortField, gbc);

        // Network info label
        JLabel networkInfoLabel = new JLabel("💡 Network: " + (detectedNetworkIP != null ? detectedNetworkIP : "Not detected"));
        networkInfoLabel.setFont(new Font("Arial", Font.PLAIN, 10));
        networkInfoLabel.setForeground(Color.GRAY);
        gbc.gridy = 4; gbc.gridx = 0; gbc.gridwidth = 3; gbc.anchor = GridBagConstraints.CENTER;
        gbc.insets = new Insets(0, 0, 10, 0);
        loginPanel.add(networkInfoLabel, gbc);

        // Test connection button
        testConnectionButton = new JButton("🔍 Test Connection");
        testConnectionButton.addActionListener(e -> testConnection());
        gbc.gridy = 5; gbc.gridx = 0; gbc.gridwidth = 3; gbc.anchor = GridBagConstraints.CENTER;
        gbc.insets = new Insets(10, 5, 10, 5);
        loginPanel.add(testConnectionButton, gbc);

        // User authentication section
        JLabel authLabel = new JLabel("🔑 User Authentication", SwingConstants.CENTER);
        authLabel.setFont(new Font("Arial", Font.BOLD, 14));
        gbc.gridy = 6; gbc.insets = new Insets(20, 0, 10, 0);
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
        gbc.gridy = 7; gbc.insets = new Insets(0, 0, 20, 0);
        loginPanel.add(accountsInfo, gbc);

        // Username
        gbc.gridwidth = 1; gbc.insets = new Insets(5, 5, 5, 5);
        gbc.gridy = 8; gbc.gridx = 0; gbc.anchor = GridBagConstraints.EAST;
        loginPanel.add(new JLabel("Username:"), gbc);

        usernameField = new JTextField(20);
        usernameField.setPreferredSize(new Dimension(200, 25));
        gbc.gridx = 1; gbc.gridwidth = 2; gbc.anchor = GridBagConstraints.WEST; gbc.fill = GridBagConstraints.HORIZONTAL;
        loginPanel.add(usernameField, gbc);

        // Password
        gbc.gridy = 9; gbc.gridx = 0; gbc.gridwidth = 1; gbc.anchor = GridBagConstraints.EAST;
        loginPanel.add(new JLabel("Password:"), gbc);

        passwordField = new JPasswordField(20);
        passwordField.setPreferredSize(new Dimension(200, 25));
        gbc.gridx = 1; gbc.gridwidth = 2; gbc.anchor = GridBagConstraints.WEST; gbc.fill = GridBagConstraints.HORIZONTAL;
        loginPanel.add(passwordField, gbc);

        // Connect button
        connectButton = new JButton("🔗 Connect to Server");
        connectButton.addActionListener(e -> connectToServer());
        gbc.gridy = 10; gbc.gridx = 0; gbc.gridwidth = 3; gbc.anchor = GridBagConstraints.CENTER;
        gbc.insets = new Insets(20, 5, 5, 5);
        loginPanel.add(connectButton, gbc);

        // Status label
        statusLabel = new JLabel("Ready to connect", SwingConstants.CENTER);
        statusLabel.setForeground(Color.BLUE);
        gbc.gridy = 11; gbc.insets = new Insets(10, 5, 5, 5);
        loginPanel.add(statusLabel, gbc);

        // Enter key listeners
        serverHostField.addActionListener(e -> serverPortField.requestFocus());
        serverPortField.addActionListener(e -> usernameField.requestFocus());
        usernameField.addActionListener(e -> passwordField.requestFocus());
        passwordField.addActionListener(e -> connectToServer());
    }

    /**
     * Auto-detect network IP and update the server host field
     */
    private void autoDetectNetwork() {
        new Thread(() -> {
            SwingUtilities.invokeLater(() -> {
                testConnectionButton.setEnabled(false);
                statusLabel.setText("🔍 Detecting network...");
                statusLabel.setForeground(Color.ORANGE);
            });

            detectNetworkIP();

            SwingUtilities.invokeLater(() -> {
                serverHostField.setText(detectedNetworkIP);
                serverHostField.setToolTipText("Detected network IP: " + detectedNetworkIP);

                // Update network info label
                Component[] components = loginPanel.getComponents();
                for (Component comp : components) {
                    if (comp instanceof JLabel && ((JLabel) comp).getText().startsWith("💡 Network:")) {
                        ((JLabel) comp).setText("💡 Network: " + detectedNetworkIP);
                        break;
                    }
                }

                statusLabel.setText("✅ Network detected: " + detectedNetworkIP);
                statusLabel.setForeground(Color.GREEN);
                testConnectionButton.setEnabled(true);
            });
        }).start();
    }

    /**
     * Test connection to server
     */
    private void testConnection() {
        updateServerSettings();

        testConnectionButton.setEnabled(false);
        statusLabel.setText("🔍 Testing connection...");
        statusLabel.setForeground(Color.ORANGE);

        new Thread(() -> {
            try {
                Socket testSocket = new Socket();
                testSocket.connect(new InetSocketAddress(serverHost, serverPort), 5000);
                testSocket.close();

                SwingUtilities.invokeLater(() -> {
                    statusLabel.setText("✅ Connection successful!");
                    statusLabel.setForeground(Color.GREEN);
                    testConnectionButton.setEnabled(true);
                });
            } catch (IOException e) {
                SwingUtilities.invokeLater(() -> {
                    statusLabel.setText("❌ Connection failed: " + e.getMessage());
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
            serverHost = DEFAULT_SERVER_HOST;
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

        sendButton = new JButton("📤 Send");
        sendButton.addActionListener(e -> sendMessage());
        inputPanel.add(sendButton, BorderLayout.EAST);

        chatPanel.add(inputPanel, BorderLayout.SOUTH);

        // Top panel with server info and controls
        JPanel topPanel = new JPanel(new BorderLayout());
        JLabel serverInfoLabel = new JLabel("🌐 Server: ");

        JPanel buttonPanel = new JPanel(new FlowLayout());

        JButton infoButton = new JButton("ℹ️ Info");
        infoButton.addActionListener(e -> showConnectionInfo());

        JButton helpButton = new JButton("❓ Help");
        helpButton.addActionListener(e -> showHelp());

        disconnectButton = new JButton("🔌 Disconnect");
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
        String info = "🌐 Connection Information\n\n" +
                "Server: " + serverHost + ":" + serverPort + "\n" +
                "Username: " + username + "\n" +
                "Encryption: AES-128\n" +
                "Status: " + (isConnected ? "Connected ✅" : "Disconnected ❌");

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
            statusLabel.setText("❌ Please enter username and password");
            statusLabel.setForeground(Color.RED);
            return;
        }

        connectButton.setEnabled(false);
        testConnectionButton.setEnabled(false);
        statusLabel.setText("🔗 Connecting to " + serverHost + ":" + serverPort + "...");
        statusLabel.setForeground(Color.ORANGE);

        // Connect in background thread
        new Thread(() -> {
            try {
                socket = new Socket(serverHost, serverPort);
                input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                output = new PrintWriter(socket.getOutputStream(), true);

                SwingUtilities.invokeLater(() -> {
                    statusLabel.setText("🔐 Authenticating...");
                });

                // Start server listener
                Thread serverListener = new Thread(this::listenForServerMessages);
                serverListener.setDaemon(true);
                serverListener.start();

                // Wait longer for server welcome messages
                Thread.sleep(1500);

                // Send credentials
                System.out.println("Sending username: " + user);
                sendEncryptedMessage(user);
                Thread.sleep(200);

                System.out.println("Sending password");
                sendEncryptedMessage(pass);

                // Wait for authentication result
                Thread.sleep(2000);

                if (isConnected) {
                    username = user;
                    SwingUtilities.invokeLater(() -> {
                        remove(loginPanel);
                        add(chatPanel);
                        validate();
                        repaint();
                        messageField.requestFocus();

                        // Update server info label
                        Component[] components = ((JPanel)chatPanel.getComponent(2)).getComponents();
                        if (components[0] instanceof JLabel) {
                            ((JLabel)components[0]).setText("🌐 Server: " + serverHost + ":" + serverPort + " | User: " + username);
                        }
                    });
                } else {
                    SwingUtilities.invokeLater(() -> {
                        statusLabel.setText("❌ Authentication failed - Check credentials");
                        statusLabel.setForeground(Color.RED);
                        connectButton.setEnabled(true);
                        testConnectionButton.setEnabled(true);
                    });
                }

            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> {
                    statusLabel.setText("❌ Connection failed: " + e.getMessage());
                    statusLabel.setForeground(Color.RED);
                    connectButton.setEnabled(true);
                    testConnectionButton.setEnabled(true);

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
                String message = decrypt(encryptedMessage);
                System.out.println("Received from server: " + message);

                SwingUtilities.invokeLater(() -> {
                    if (message.contains("Authentication successful") || message.contains("Welcome")) {
                        isConnected = true;
                        System.out.println("Authentication successful detected!");
                    } else if (message.contains("Invalid credentials") || message.contains("already logged")) {
                        isConnected = false;
                        System.out.println("Authentication failed detected!");
                        return;
                    }

                    // Only add to chat area if we're in chat mode (connected)
                    if (isConnected && chatArea != null) {
                        // Add timestamp and display message
                        String timestamp = new SimpleDateFormat("HH:mm:ss").format(new Date());
                        chatArea.append("[" + timestamp + "] " + message + "\n");
                        chatArea.setCaretPosition(chatArea.getDocument().getLength());
                    }
                });
            }
        } catch (IOException e) {
            if (isConnected) {
                SwingUtilities.invokeLater(() -> {
                    if (chatArea != null) {
                        chatArea.append("\n❌ Lost connection to server.\n");
                        chatArea.append("💡 Server might be down or network issues occurred.\n");
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
                chatArea.append("[" + timestamp + "] 📤 You: " + message + "\n");
            } else {
                // For regular messages, show as sent
                chatArea.append("[" + timestamp + "] 📤 " + username + ": " + message + "\n");
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
        String helpText = "📋 Available Commands:\n\n" +
                "/list - Show online users\n" +
                "/private <user> <message> - Send private message\n" +
                "/info - Show connection info\n" +
                "/quit - Exit chat\n\n" +
                "💡 Tips:\n" +
                "• All messages are encrypted with AES-128\n" +
                "• Press Enter to send messages\n" +
                "• Private messages are shown in chat area\n" +
                "• Use /list to see who's online\n" +
                "• Test connection before connecting\n\n" +
                "🌐 Multi-PC Support:\n" +
                "• Enter server IP address in login screen\n" +
                "• Default port is 30703\n" +
                "• Use Test Connection to verify connectivity";

        JOptionPane.showMessageDialog(this, helpText, "Help", JOptionPane.INFORMATION_MESSAGE);
    }

    /**
     * Encrypt and send message
     */
    private void sendEncryptedMessage(String message) {
        if (output != null && isConnected) {
            String encryptedMessage = encrypt(message);
            output.println(encryptedMessage);
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
            return encryptedMessage;
        }
    }

    /**
     * Disconnect from server
     */
    private void disconnect() {
        if (isConnected) {
            sendEncryptedMessage("/quit");
        }

        isConnected = false;
        try {
            if (input != null) input.close();
            if (output != null) output.close();
            if (socket != null) socket.close();
        } catch (IOException e) {
            // Ignore cleanup errors
        }

        SwingUtilities.invokeLater(() -> {
            if (chatPanel.getParent() != null) {
                remove(chatPanel);
                add(loginPanel);
                validate();
                repaint();
                connectButton.setEnabled(true);
                testConnectionButton.setEnabled(true);
                statusLabel.setText("👋 Disconnected from " + serverHost + ":" + serverPort);
                statusLabel.setForeground(Color.BLUE);
                usernameField.setText("");
                passwordField.setText("");
            }
        });
    }

    /**
     * Main method
     */
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            // Simple main method without look and feel complications
            new SecureChatClientGUI().setVisible(true);
        });
    }
}