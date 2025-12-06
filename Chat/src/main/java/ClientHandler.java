import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.Cipher;
import javax.crypto.spec.*;
import java.util.Base64;

import Security.CryptoUtils;
import Security.SecurityContext;

public class ClientHandler implements Runnable {
    private final Socket clientSocket;
    private final SecurityContext securityContext = new SecurityContext();

    private PrivateKey serverPrivateKey;
    private PublicKey clientPublicKey;
    private SecretKeySpec aesKeySpec;
    private PrintWriter out;
    private BufferedReader in;

    private String clientName = "Inconnu";
    private boolean authenticated = false;

    public ClientHandler(Socket socket) {
        this.clientSocket = socket;

        // ** CORRECTION : SUPPRESSION DE L'INITIALISATION RSA REDONDANTE **
        /* try {
            // S'assurer que la clé privée du serveur est initialisée
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            serverPrivateKey = kpg.generateKeyPair().getPrivate();
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Erreur d'initialisation de clé RSA: " + e.getMessage());
        }
        */
        // La clé sera générée dans performHandshake() où la clé publique est envoyée.
    }

    public String getClientName() { return clientName; }
    public boolean isAuthenticated() { return authenticated; }

    public void sendMessage(String plainMessage) {
        if (!authenticated) {
            System.out.println("⚠️ [WARN] Tentative d'envoi broadcast non authentifiée ignorée.");
            return;
        }
        try {
            String securedMessage = securityContext.addSecurityHeaders(plainMessage);
            String encryptedReply = CryptoUtils.signAndEncrypt(securedMessage, serverPrivateKey, aesKeySpec);

            out.println(encryptedReply);
            out.flush();
        } catch (Exception e) {
            System.out.println("❌ Erreur lors de l'envoi à " + clientName + ": " + e.getMessage());
        }
    }


    @Override
    public void run() {
        try {
            out = new PrintWriter(clientSocket.getOutputStream(), true);
            in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

            // --- ÉTAPE 1: Poignée de main de sécurité (Handshake) ---
            performHandshake();

            // --- ÉTAPE 2: Authentification ---
            String authRequestEncrypted = in.readLine();
            if (authRequestEncrypted == null) throw new SecurityException("Requête d'authentification manquante.");

            // ** Note: Cette ligne utilise serverPrivateKey et aesKeySpec générés dans performHandshake()
            String authRequestSecured = CryptoUtils.verifyAndDecrypt(authRequestEncrypted, clientPublicKey, aesKeySpec, securityContext);

            processAuth(authRequestSecured);

            // --- ÉTAPE 3: Communication ---
            if (authenticated) {
                String encryptedMessage;
                while ((encryptedMessage = in.readLine()) != null) {
                    processEncryptedMessage(encryptedMessage);
                }
            }

        } catch (SecurityException se) {
            System.err.println(" [ERREUR SÉCU] " + se.getMessage() + ". Déconnexion de " + clientName);
            try {
                sendAuthResponse(false, "Échec de la vérification de sécurité: " + se.getMessage());
            } catch (Exception ignore) { /* ignore */ }
        } catch (IOException e) {
            System.out.println(" Client " + clientName + " déconnecté (IO Exception: " + e.getMessage() + ")");
        } catch (Exception e) {
            System.err.println(" Erreur fatale dans ClientHandler pour " + clientName + ": " + e.getMessage());
        } finally {
            closeConnection();
        }
    }

    private void performHandshake() throws Exception {
        // Générer les clés du serveur pour cette session
        KeyPair serverKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        serverPrivateKey = serverKeyPair.getPrivate();
        PublicKey serverPublicKey = serverKeyPair.getPublic();

        // 1. Envoyer la clé publique du serveur (B64)
        String serverPubKeyB64 = Base64.getEncoder().encodeToString(serverPublicKey.getEncoded());
        out.println(serverPubKeyB64);
        out.flush();
        System.out.println("✅ [HANDSHAKE] Clé publique serveur envoyée");

        // 2. Recevoir la clé AES chiffrée (CORRECT - le client l'envoie maintenant en premier)
        String encryptedAESKeyB64 = in.readLine();
        if (encryptedAESKeyB64 == null) throw new SecurityException("Clé AES chiffrée manquante");
        byte[] encryptedAESKeyBytes = Base64.getDecoder().decode(encryptedAESKeyB64);

        // Déchiffrer la clé AES avec la clé privée du serveur
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.DECRYPT_MODE, serverPrivateKey);
        byte[] aesKeyBytes = rsaCipher.doFinal(encryptedAESKeyBytes);
        aesKeySpec = new SecretKeySpec(aesKeyBytes, "AES");
        System.out.println("✅ [HANDSHAKE] Clé AES reçue et décryptée");


        // 3. Recevoir la clé publique du client (POUR SIGNATURES) (CORRECT - le client l'envoie maintenant en second)
        String clientPubKeyB64 = in.readLine();
        if (clientPubKeyB64 == null) throw new SecurityException("Clé publique client manquante");
        byte[] clientPubKeyBytes = Base64.getDecoder().decode(clientPubKeyB64);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        clientPublicKey = kf.generatePublic(new X509EncodedKeySpec(clientPubKeyBytes));
        System.out.println("✅ [HANDSHAKE] Clé publique client reçues");


        // 4. Confirmation de l'établissement de la sécurité
        String secureConfirm = securityContext.addSecurityHeaders("SECURE-HANDSHAKE-OK");
        String encryptedConfirm = CryptoUtils.signAndEncrypt(secureConfirm, serverPrivateKey, aesKeySpec);
        out.println(encryptedConfirm);
        out.flush();

        System.out.println("✅ [HANDSHAKE] Poignée de main sécurisée terminée avec " + clientSocket.getRemoteSocketAddress());
    }

    private void processAuth(String authRequestSecured) throws Exception {
        // Le format attendu est "/LOGIN:USERNAME:PASSWORD"
        String[] parts = authRequestSecured.split(":");
        String username = parts[1];

        if (authenticateUser(username, "")) { // Simplification
            this.clientName = username;
            this.authenticated = true;
            sendAuthResponse(true, "Bienvenue " + username);

            Serveur.addClient(this);
            Serveur.broadcast(username + " a rejoint le chat.", this);

        } else {
            this.authenticated = false;
            sendAuthResponse(false, "Identifiants incorrects");
        }
    }

    private void processEncryptedMessage(String encryptedMessage) throws Exception {
        String decryptedMessage = CryptoUtils.verifyAndDecrypt(encryptedMessage, clientPublicKey, aesKeySpec, securityContext);

        if (decryptedMessage.startsWith("PM:")) {
            // Commande PM:DESTINATAIRE:MESSAGE
            String pmContent = decryptedMessage.substring(3);
            String[] parts = pmContent.split(":", 2);
            if (parts.length == 2) {
                String recipient = parts[0];
                String message = parts[1];
                Serveur.privateMessage(recipient, clientName, message);
            }
        } else {
            // Message de chat général
            String fullMessage = clientName + " : " + decryptedMessage;
            Serveur.broadcast(fullMessage, this);
        }

        if (decryptedMessage.equalsIgnoreCase("bye")) {
            throw new IOException("Client a envoyé 'bye'.");
        }
    }

    private void sendAuthResponse(boolean success, String message) throws Exception {
        String response = success ? "AUTH_OK:" + message : "AUTH_FAIL:" + message;

        String securedMsg = securityContext.addSecurityHeaders(response);
        String encryptedMsg = CryptoUtils.signAndEncrypt(securedMsg, serverPrivateKey, aesKeySpec);

        out.println(encryptedMsg);
        out.flush();
    }

    private boolean authenticateUser(String username, String password) {
        return true;
    }

    private void closeConnection() {
        try {
            if (in != null) in.close();
            if (out != null) out.close();
            if (clientSocket != null && !clientSocket.isClosed()) clientSocket.close();

            if (authenticated) {
                Serveur.removeClient(this, clientName);
            }
        } catch (IOException e) {
            // Ignorer
        }
    }
}