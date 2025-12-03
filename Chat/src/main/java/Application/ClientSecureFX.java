package Application;

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Base64;

// Utilise la version du SecurityContextFX pour l'application graphique
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

    public ClientSecureFX(String host, int port, String username) throws Exception {
        this.username = username;
        this.socket = new Socket(host, port);
        this.in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        this.out = new PrintWriter(socket.getOutputStream(), true);
        performHandshake();
    }

    private void performHandshake() throws Exception {
        // --- ÉTAPE 1: Échange de clés publiques RSA ---
        // ... (Logique identique à ClientSecure)
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
        // Utilisation de la classe statique CryptoUtils
        CryptoUtilsFX.verifyAndDecrypt(serverConfirmEncrypted, serverPublicKey, aesKeySpec, new SecurityContextFX());
    }

    // Logique BLOCANTE pour l'authentification (attend la réponse AUTH_OK/FAIL)
    public void sendLoginCredentials(String username, String password) throws Exception {
        String loginMessage = "/LOGIN:" + username + ":" + password;

        // Signature et Chiffrement du message de login
        String securedMsg = securityContext.addSecurityHeaders(loginMessage);
        String encryptedMsg = CryptoUtilsFX.signAndEncrypt(securedMsg, clientPrivateKey, aesKeySpec);
        out.println(encryptedMsg);

        // ATTENTE BLOQUANTE de la réponse du serveur
        String authResponseEncrypted = in.readLine();
        if (authResponseEncrypted == null) {
            throw new SecurityException("Réponse d'authentification manquante.");
        }

        // Vérification et Décryptage de la réponse
        String decryptedResponse = CryptoUtilsFX.verifyAndDecrypt(authResponseEncrypted, serverPublicKey, aesKeySpec, new SecurityContextFX());

        if (!decryptedResponse.startsWith("AUTH_OK")) {
            String reason = decryptedResponse.substring(decryptedResponse.indexOf(':') + 1).trim();
            throw new SecurityException("Authentification refusée: " + reason);
        }
    }

    public void sendSecuredMessage(String rawMessage) throws Exception {
        // Le serveur gérera l'ajout du nom d'utilisateur.
        String securedMsg = securityContext.addSecurityHeaders(rawMessage);
        String encryptedMsg = CryptoUtilsFX.signAndEncrypt(securedMsg, clientPrivateKey, aesKeySpec);
        out.println(encryptedMsg);
    }

    // Lance le thread d'écoute qui met à jour l'interface graphique via le contrôleur
    public void startListening(ClientController controller) {
        new Thread(() -> {
            try {
                String serverResponse;
                while ((serverResponse = in.readLine()) != null) {
                    // Vérification et décryptage
                    String decryptedResponse = CryptoUtilsFX.verifyAndDecrypt(serverResponse, serverPublicKey, aesKeySpec, new SecurityContextFX());

                    // Affichage dans l'interface graphique
                    controller.displayMessage(decryptedResponse);
                }
            } catch (Exception e) {
                if (!socket.isClosed()) {
                    controller.displayMessage("[ERREUR] Connexion perdue: " + e.getMessage());
                }
            }
            controller.displayMessage("Connexion avec le serveur fermée.");
        }).start();
    }

    public void closeConnection() {
        try {
            if (socket != null) socket.close();
        } catch (IOException e) {
            System.err.println("Erreur lors de la fermeture des ressources: " + e.getMessage());
        }
    }
}