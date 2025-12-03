package appFX;

import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.stage.Stage;

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import Security.CryptoUtils;
import Security.SecurityContext;

public class ClientSecureFX {
    public static final String SERVER_HOST = "localhost";
    public static final int SERVER_PORT = 5000;

    private String username;
    private ChatView chatView;
    Socket socket;
    private PrintWriter out;
    private BufferedReader in;
    private Thread readerThread;

    private KeyPair clientKeyPair;
    private PrivateKey clientPrivateKey;
    private PublicKey serverPublicKey;
    private SecretKeySpec aesKeySpec;
    private SecurityContext securityContext = new SecurityContext();

    public final ObservableList<String> userList = FXCollections.observableArrayList();
    private Map<String, PrivateChatView> privateChatWindows = new HashMap<>();


    public ClientSecureFX(String username, ChatView view) throws Exception {
        this.username = username;
        this.chatView = view;

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        clientKeyPair = kpg.generateKeyPair();
        this.clientPrivateKey = clientKeyPair.getPrivate();
    }

    public String getUsername() {
        return username;
    }

    public void setChatView(ChatView chatView) {
        this.chatView = chatView;
    }

    public void startConnection() throws Exception {
        try {
            socket = new Socket(SERVER_HOST, SERVER_PORT);
            out = new PrintWriter(socket.getOutputStream(), true);
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            // 1. Handshake
            String serverPubKeyB64 = in.readLine();
            if (serverPubKeyB64 == null) throw new SecurityException("Clé publique serveur manquante");

            // Récupérer et stocker la clé publique du serveur
            byte[] serverPubKeyBytes = Base64.getDecoder().decode(serverPubKeyB64);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(serverPubKeyBytes);
            this.serverPublicKey = kf.generatePublic(keySpec);

            // Générer et chiffrer la clé AES
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(128);
            SecretKey aesKey = kg.generateKey();
            aesKeySpec = new SecretKeySpec(aesKey.getEncoded(), "AES");

            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
            byte[] encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());

            // Envoi de la clé AES chiffrée
            out.println(Base64.getEncoder().encodeToString(encryptedAesKey));

            // Envoi de la clé publique du client
            String clientPubKeyB64 = Base64.getEncoder().encodeToString(clientKeyPair.getPublic().getEncoded());
            out.println(clientPubKeyB64);

            // Lecture de la confirmation de sécurité
            String serverConfirmEncrypted = in.readLine();
            CryptoUtils.verifyAndDecrypt(serverConfirmEncrypted, serverPublicKey, aesKeySpec, securityContext);


            // 2. Authentification
            String authRequest = "/LOGIN:" + username + ":password";
            String securedAuth = securityContext.addSecurityHeaders(authRequest);
            String encryptedAuth = CryptoUtils.signAndEncrypt(securedAuth, clientPrivateKey, aesKeySpec);
            out.println(encryptedAuth);

            String authResponseEncrypted = in.readLine();
            String authResponse = CryptoUtils.verifyAndDecrypt(authResponseEncrypted, serverPublicKey, aesKeySpec, securityContext);

            if (authResponse.startsWith("AUTH_FAIL")) {
                throw new SecurityException("Authentification échouée: " + authResponse.split(":")[1]);
            }

            // 3. Lancement du thread d'écoute
            readerThread = new Thread(new ClientReaderFX(this, in));
            readerThread.start();

        } catch (Exception e) {
            disconnect();
            throw e;
        }
    }

    public void disconnect() {
        if (socket != null && !socket.isClosed()) {
            try {
                // Envoi d'un message 'bye' au serveur
                String securedMsg = securityContext.addSecurityHeaders("bye");
                String encryptedMsg = CryptoUtils.signAndEncrypt(securedMsg, clientPrivateKey, aesKeySpec);
                out.println(encryptedMsg);

                if (readerThread != null) {
                    readerThread.interrupt();
                }
                socket.close();
            } catch (Exception e) {
                System.err.println("Erreur lors de la déconnexion: " + e.getMessage());
            }
        }
    }

    public void sendMessage(String message) throws Exception {
        if (out == null || socket.isClosed()) {
            throw new IllegalStateException("Non connecté au serveur.");
        }
        String securedMsg = securityContext.addSecurityHeaders(message);
        String encryptedMsg = CryptoUtils.signAndEncrypt(securedMsg, clientPrivateKey, aesKeySpec);
        out.println(encryptedMsg);
    }

    public void sendPrivateMessage(String recipient, String message) throws Exception {
        if (out == null || socket.isClosed()) {
            throw new IllegalStateException("Non connecté au serveur.");
        }

        // Format de la commande PM envoyée au serveur: PM:DESTINATAIRE:MESSAGE_CLAIR
        String securedMsg = securityContext.addSecurityHeaders("PM:" + recipient + ":" + message);

        String encryptedMsg = CryptoUtils.signAndEncrypt(securedMsg, clientPrivateKey, aesKeySpec);
        out.println(encryptedMsg);
    }

    public void appendGeneralMessage(String message) {
        Platform.runLater(() -> chatView.appendMessage("CHAT", message));
    }

    public void handleUserList(String users) {
        String[] userArray = users.split(",");

        Platform.runLater(() -> {
            userList.clear();
            for (String user : userArray) {
                if (!user.isEmpty()) {
                    String display = user.equals(username) ? user + " (Moi)" : user;
                    userList.add(display);
                }
            }
            userList.sort((u1, u2) -> {
                if (u1.contains("(Moi)")) return -1;
                if (u2.contains("(Moi)")) return 1;
                return u1.compareTo(u2);
            });
        });
    }

    public void handlePrivateMessage(String sender, String message) {
        Platform.runLater(() -> {
            PrivateChatView chat = privateChatWindows.get(sender);
            if (chat == null) {
                Stage newStage = new Stage();
                PrivateChatView newChat = new PrivateChatView(newStage, this, sender);
                privateChatWindows.put(sender, newChat);
                newChat.show();
                chat = newChat;
            }
            chat.appendMessage(sender, message);
        });
    }

    public void closePrivateChat(String recipient) {
        privateChatWindows.remove(recipient);
    }

    public PublicKey getServerPublicKey() { return serverPublicKey; }
    public SecretKeySpec getAesKeySpec() { return aesKeySpec; }
    public SecurityContext getSecurityContext() { return securityContext; }
    // appFX/ClientSecureFX.java (Nouvelle méthode)

    public Map<String, PrivateChatView> getPrivateChatWindows() {
        return privateChatWindows;
    }
}