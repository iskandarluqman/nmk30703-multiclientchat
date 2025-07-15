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

/**
 * Secure Chat Client with GUI
 * User-friendly graphical interface for the secure chat application
 */
public class SecureChatClientGUI extends JFrame {
    private static final String SERVER_HOST = "localhost";
    private static final int SERVER_PORT = 30703;
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
    private JPanel loginPanel;
    private JPanel chatPanel;

    // Networking components
    private Socket socket;
    private BufferedReader input;
    private PrintWriter output;
    private boolean isConnected = false;
    private Cipher encryptCipher;
    private Cipher decryptCipher;
    private String username;

    public SecureChatClientGUI() {
        setupEncryption();
        initializeGUI();
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
        setTitle("🔐 Secure Chat Client");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(600, 500);
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

        // Server info
        JLabel serverLabel = new JLabel("Server: " + SERVER_HOST + ":" + SERVER_PORT);
        serverLabel.setFont(new Font("Arial", Font.PLAIN, 12));
        gbc.gridy = 1; gbc.insets = new Insets(0, 0, 10, 0);
        loginPanel.add(serverLabel, gbc);

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
        gbc.gridy = 2; gbc.insets = new Insets(0, 0, 20, 0);
        loginPanel.add(accountsInfo, gbc);

        // Username
        gbc.gridwidth = 1; gbc.insets = new Insets(5, 5, 5, 5);
        gbc.gridy = 3; gbc.gridx = 0; gbc.anchor = GridBagConstraints.EAST;
        loginPanel.add(new JLabel("Username:"), gbc);

        usernameField = new JTextField(15);
        gbc.gridx = 1; gbc.anchor = GridBagConstraints.WEST;
        loginPanel.add(usernameField, gbc);

        // Password
        gbc.gridy = 4; gbc.gridx = 0; gbc.anchor = GridBagConstraints.EAST;
        loginPanel.add(new JLabel("Password:"), gbc);

        passwordField = new JPasswordField(15);
        gbc.gridx = 1; gbc.anchor = GridBagConstraints.WEST;
        loginPanel.add(passwordField, gbc);

        // Connect button
        connectButton = new JButton("🔗 Connect");
        connectButton.addActionListener(e -> connectToServer());
        gbc.gridy = 5; gbc.gridx = 0; gbc.gridwidth = 2; gbc.anchor = GridBagConstraints.CENTER;
        gbc.insets = new Insets(20, 5, 5, 5);
        loginPanel.add(connectButton, gbc);

        // Status label
        statusLabel = new JLabel("Ready to connect", SwingConstants.CENTER);
        statusLabel.setForeground(Color.BLUE);
        gbc.gridy = 6; gbc.insets = new Insets(10, 5, 5, 5);
        loginPanel.add(statusLabel, gbc);

        // Enter key listeners
        usernameField.addActionListener(e -> passwordField.requestFocus());
        passwordField.addActionListener(e -> connectToServer());
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

        // Top panel with user info and controls
        JPanel topPanel = new JPanel(new BorderLayout());
        JLabel userLabel = new JLabel("👤 User: ");

        disconnectButton = new JButton("🔌 Disconnect");
        disconnectButton.addActionListener(e -> disconnect());

        JButton helpButton = new JButton("❓ Help");
        helpButton.addActionListener(e -> showHelp());

        JPanel buttonPanel = new JPanel(new FlowLayout());
        buttonPanel.add(helpButton);
        buttonPanel.add(disconnectButton);

        topPanel.add(userLabel, BorderLayout.WEST);
        topPanel.add(buttonPanel, BorderLayout.EAST);
        chatPanel.add(topPanel, BorderLayout.NORTH);
    }

    /**
     * Connect to server
     */
    private void connectToServer() {
        String user = usernameField.getText().trim();
        String pass = new String(passwordField.getPassword());

        if (user.isEmpty() || pass.isEmpty()) {
            statusLabel.setText("❌ Please enter username and password");
            statusLabel.setForeground(Color.RED);
            return;
        }

        connectButton.setEnabled(false);
        statusLabel.setText("🔗 Connecting...");
        statusLabel.setForeground(Color.ORANGE);

        // Connect in background thread
        new Thread(() -> {
            try {
                socket = new Socket(SERVER_HOST, SERVER_PORT);
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

                // Send credentials with debugging
                System.out.println("Sending username: " + user);
                sendEncryptedMessage(user);
                Thread.sleep(200);

                System.out.println("Sending password");
                sendEncryptedMessage(pass);

                // Wait longer for authentication result
                Thread.sleep(2000);

                if (isConnected) {
                    username = user;
                    SwingUtilities.invokeLater(() -> {
                        remove(loginPanel);
                        add(chatPanel);
                        validate();
                        repaint();
                        messageField.requestFocus();

                        // Update user label
                        Component[] components = ((JPanel)chatPanel.getComponent(2)).getComponents();
                        if (components[0] instanceof JLabel) {
                            ((JLabel)components[0]).setText("👤 User: " + username);
                        }
                    });
                } else {
                    SwingUtilities.invokeLater(() -> {
                        statusLabel.setText("❌ Authentication failed - Check credentials");
                        statusLabel.setForeground(Color.RED);
                        connectButton.setEnabled(true);
                    });
                }

            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> {
                    statusLabel.setText("❌ Connection failed: " + e.getMessage());
                    statusLabel.setForeground(Color.RED);
                    connectButton.setEnabled(true);
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
                System.out.println("Received from server: " + message); // Debug output

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
                "/quit - Exit chat\n\n" +
                "💡 Tips:\n" +
                "• All messages are encrypted with AES-128\n" +
                "• Press Enter to send messages\n" +
                "• Private messages are shown in chat area\n" +
                "• Use /list to see who's online";

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
                statusLabel.setText("👋 Disconnected");
                statusLabel.setForeground(Color.BLUE);
                usernameField.setText("");
                passwordField.setText("");
            }
        });
    }

    /**
     * Main method - SIMPLIFIED VERSION (NO LOOK AND FEEL ISSUES)
     */
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            new SecureChatClientGUI().setVisible(true);
        });
    }
}
