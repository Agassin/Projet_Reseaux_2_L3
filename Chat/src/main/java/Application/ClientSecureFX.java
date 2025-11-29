package Application;

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Base64;

public class ClientSecureFX {
    public static final String SERVER_HOST = "localhost";
    public static final int SERVER_PORT = 5000;

    private final SecurityContextFX securityContext = new SecurityContextFX();
    private PrivateKey clientPrivateKey;
    private PublicKey serverPublicKey;
    private SecretKeySpec aesKeySpec;
    private PrintWriter out;
    private BufferedReader in;
    private final String username;
    private Socket socket;

    // Constructeur : gère uniquement la connexion et le Handshake.
    public ClientSecureFX(String host, int port, String username) throws Exception {
        this.username = username;
        this.socket = new Socket(host, port);
        this.in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        this.out = new PrintWriter(socket.getOutputStream(), true);
        performHandshake();
    }

    private void performHandshake() throws Exception {
        // --- ÉTAPE 1: Échange de clés publiques RSA ---
        String serverPubKeyB64 = in.readLine();
        if (serverPubKeyB64 == null) throw new SecurityException("Clé publique serveur manquante");
        byte[] serverPubKeyBytes = Base64.getDecoder().decode(serverPubKeyB64);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(serverPubKeyBytes);
        this.serverPublicKey = kf.generatePublic(keySpec);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair clientKeyPair = kpg.generateKeyPair();
        this.clientPrivateKey = clientKeyPair.getPrivate();
        String clientPubKeyB64 = Base64.getEncoder().encodeToString(clientKeyPair.getPublic().getEncoded());
        out.println(clientPubKeyB64);

        // --- ÉTAPE 2: Échange de clé AES sécurisé ---
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        SecretKey aesKey = kg.generateKey();
        this.aesKeySpec = new SecretKeySpec(aesKey.getEncoded(), "AES");

        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
        byte[] encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());
        String encryptedAesKeyB64 = Base64.getEncoder().encodeToString(encryptedAesKey);
        out.println(encryptedAesKeyB64);

        // --- ÉTAPE 3: Confirmation de sécurité ---
        String serverConfirmEncrypted = in.readLine();
        CryptoUtilsFX.verifyAndDecrypt(serverConfirmEncrypted, serverPublicKey, aesKeySpec, securityContext);
    }

    // NOUVELLE LOGIQUE BLOQUANTE POUR L'AUTHENTIFICATION
    public void sendLoginCredentials(String username, String password) throws Exception {
        String loginMessage = "/LOGIN:" + username + ":" + password;

        String securedMsg = securityContext.addSecurityHeaders(loginMessage);
        String encryptedMsg = CryptoUtilsFX.signAndEncrypt(securedMsg, clientPrivateKey, aesKeySpec);
        out.println(encryptedMsg);

        // 🚨 ATTENDRE LA RÉPONSE DU SERVEUR
        String authResponseEncrypted = in.readLine();
        if (authResponseEncrypted == null) {
            throw new SecurityException("Réponse d'authentification manquante ou connexion interrompue.");
        }

        String decryptedResponse = CryptoUtilsFX.verifyAndDecrypt(authResponseEncrypted, serverPublicKey, aesKeySpec, securityContext);

        if (!decryptedResponse.startsWith("AUTH_OK")) {
            // Le serveur doit renvoyer "AUTH_FAIL: [raison]"
            String reason = decryptedResponse.substring(decryptedResponse.indexOf(':') + 1).trim();
            throw new SecurityException("Authentification refusée par le serveur. (" + reason + ")");
        }
    }

    public void sendSecuredMessage(String rawMessage) throws Exception {
        String fullMessage = username + ": " + rawMessage;
        String securedMsg = securityContext.addSecurityHeaders(fullMessage);
        String encryptedMsg = CryptoUtilsFX.signAndEncrypt(securedMsg, clientPrivateKey, aesKeySpec);
        out.println(encryptedMsg);
        if (rawMessage.equalsIgnoreCase("bye")) {
            closeConnection();
        }
    }

    public void startListening(ClientController controller) {
        new Thread(() -> {
            try {
                String serverResponse;
                while ((serverResponse = in.readLine()) != null) {
                    String decryptedResponse = CryptoUtilsFX.verifyAndDecrypt(serverResponse, serverPublicKey, aesKeySpec, securityContext);
                    controller.displayMessage("[CHAT] " + decryptedResponse);
                    if (decryptedResponse.toLowerCase().contains("au revoir")) {
                        break;
                    }
                }
            } catch (Exception e) {
                if (!socket.isClosed()) {
                    controller.displayMessage("[ERREUR] Connexion perdue : " + e.getMessage());
                }
            }
            controller.displayMessage("Connexion avec le serveur fermée.");
        }).start();
    }

    public void closeConnection() {
        try {
            if (in != null) in.close();
            if (out != null) out.close();
            if (socket != null) socket.close();
        } catch (IOException e) {
            System.err.println("Erreur lors de la fermeture des ressources: " + e.getMessage());
        }
    }
}