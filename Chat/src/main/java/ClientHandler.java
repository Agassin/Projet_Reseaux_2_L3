import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.Cipher;
import javax.crypto.spec.*;
import java.util.Base64;

// Chaque instance de cette classe gère un client dans un thread séparé.
public class ClientHandler implements Runnable {
    private final Socket clientSocket;
    private final SecurityContext securityContext = new SecurityContext();
    // Le SecurityContext est maintenant thread-safe (méthodes synchronisées).

    // Attributs pour la communication sécurisée avec ce client spécifique
    private PrivateKey serverPrivateKey;
    private PublicKey clientPublicKey;
    private SecretKeySpec aesKeySpec;
    private PrintWriter out;
    private BufferedReader in;

    private String clientName = "Inconnu";
    private boolean authenticated = false; // Flag d'authentification

    public ClientHandler(Socket socket) {
        this.clientSocket = socket;
    }

    /**
     * Méthode publique appelée par Serveur.broadcast() pour envoyer un message à ce client.
     * Le message est signé et chiffré avant l'envoi.
     */
    public void sendMessage(String plainMessage) {
        if (!authenticated) {
            System.out.println("⚠️ [WARN] Tentative d'envoi broadcast non authentifiée ignorée.");
            return;
        }
        try {
            String securedMessage = securityContext.addSecurityHeaders(plainMessage);
            String encryptedReply = CryptoUtils.signAndEncrypt(securedMessage, serverPrivateKey, aesKeySpec);
            out.println(encryptedReply);
            out.flush(); // IMPORTANT : Forcer l'envoi
        } catch (Exception e) {
            System.out.println("❌ Erreur lors de l'envoi broadcast à " + clientName + ": " + e.getMessage());
        }
    }

    @Override
    public void run() {
        try {
            this.out = new PrintWriter(clientSocket.getOutputStream(), true);
            this.in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

            performHandshake();

            String encryptedClientMessage;

            // Boucle d'écoute principale
            while ((encryptedClientMessage = in.readLine()) != null) {
                try {
                    // Vérification, décryptage, vérification des headers de sécurité (sequence, timestamp)
                    String decryptedMessageWithHeaders = CryptoUtils.verifyAndDecrypt(
                            encryptedClientMessage, clientPublicKey, aesKeySpec, securityContext
                    );

                    // Le contenu réel du message est la troisième partie après les headers de sécurité
                    String message = decryptedMessageWithHeaders;

                    if (message.startsWith("/LOGIN:")) {
                        // 1. Traiter l'authentification
                        handleLogin(message);
                    } else if (authenticated) {
                        // 2. Si authentifié, traiter comme un message de chat normal
                        System.out.println("💬 Reçu (clair) de " + clientName + " : " + message);

                        if (message.toLowerCase().contains("bye") || message.toLowerCase().contains("au revoir")) {
                            sendMessage("Au revoir " + clientName + " !");
                            break;
                        }

                        // DIFFUSION DU MESSAGE REÇU
                        Serveur.broadcast(clientName + " : " + message, this);
                    } else {
                        System.out.println("❌ Message ignoré (non authentifié) : " + message);
                        // Optionnel : fermer la connexion si un message est envoyé avant login
                    }

                } catch (SecurityException e) {
                    System.out.println("🚨 [ALERTE SÉCU] Message rejeté de " + clientName + " : " + e.getMessage());
                    sendAuthResponse(false, "Security violation: " + e.getMessage());
                    // Optionnel: break pour déconnecter le client après une violation
                }
            }

        } catch (SocketException e) {
            System.out.println("ℹ️ Connexion fermée pour " + clientName + ".");
        } catch (Exception e) {
            System.err.println("❌ Erreur inattendue pour " + clientName + ": " + e.getMessage());
            e.printStackTrace();
        } finally {
            closeConnection();
            Serveur.removeClient(this, clientName);
        }
    }

    private void performHandshake() throws Exception {
        System.out.println("🔐 [HANDSHAKE] Début avec " + clientSocket.getRemoteSocketAddress());

        // 1. Génération et envoi de la clé publique du serveur
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        this.serverPrivateKey = kp.getPrivate();
        PublicKey serverPublicKey = kp.getPublic();
        String pubKeyB64 = Base64.getEncoder().encodeToString(serverPublicKey.getEncoded());
        out.println(pubKeyB64);
        out.flush();

        // 2. Réception de la clé publique du client
        String clientPubKeyB64 = in.readLine();
        if (clientPubKeyB64 == null) throw new SecurityException("Clé publique client manquante");
        byte[] clientPubKeyBytes = Base64.getDecoder().decode(clientPubKeyB64);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(clientPubKeyBytes);
        this.clientPublicKey = kf.generatePublic(keySpec);

        // 3. Réception et déchiffrement de la clé AES
        String encryptedAesKeyB64 = in.readLine();
        if (encryptedAesKeyB64 == null) throw new SecurityException("Clé AES manquante");
        byte[] encryptedAesKey = Base64.getDecoder().decode(encryptedAesKeyB64);
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.DECRYPT_MODE, serverPrivateKey);
        byte[] aesKeyBytes = rsaCipher.doFinal(encryptedAesKey);
        this.aesKeySpec = new SecretKeySpec(aesKeyBytes, "AES");

        // 4. Confirmation de l'établissement de la sécurité
        String secureConfirm = securityContext.addSecurityHeaders("SECURE-HANDSHAKE-OK");
        String encryptedConfirm = CryptoUtils.signAndEncrypt(secureConfirm, serverPrivateKey, aesKeySpec);
        out.println(encryptedConfirm);
        out.flush();

        System.out.println("✅ [HANDSHAKE] Poignée de main sécurisée terminée avec " + clientSocket.getRemoteSocketAddress());
    }

    // Gère la commande /LOGIN:
    private void handleLogin(String loginCommand) throws Exception {
        // Format attendu: /LOGIN:username:password
        String[] parts = loginCommand.split(":", 3);

        if (parts.length < 3) {
            sendAuthResponse(false, "Format de login invalide");
            return;
        }

        String username = parts[1].trim();
        String password = parts[2].trim();

        System.out.println("🔐 [AUTH] Tentative - Username: " + username + ", Password: ***");

        boolean isValid = authenticateUser(username, password);

        if (isValid) {
            this.clientName = username;
            this.authenticated = true;
            System.out.println("✅ [AUTH] Authentification RÉUSSIE pour: " + username);
            sendAuthResponse(true, "Bienvenue " + username);
        } else {
            this.authenticated = false;
            System.out.println("❌ [AUTH] Authentification ÉCHOUÉE pour: " + username);
            sendAuthResponse(false, "Identifiants incorrects");
        }
    }

    // Envoie la réponse d'authentification (AUTH_OK ou AUTH_FAIL)
    private void sendAuthResponse(boolean success, String message) throws Exception {
        String response = success ? "AUTH_OK:" + message : "AUTH_FAIL:" + message;

        System.out.println("📤 [AUTH] Envoi réponse: " + response);

        // Sécuriser le message (ajouter headers, signer, chiffrer)
        String securedMsg = securityContext.addSecurityHeaders(response);
        String encryptedMsg = CryptoUtils.signAndEncrypt(securedMsg, serverPrivateKey, aesKeySpec);

        out.println(encryptedMsg);
        out.flush();

        System.out.println("✅ [AUTH] Réponse envoyée et flushée");
    }

    // Valider les credentials (Mode Test)
    private boolean authenticateUser(String username, String password) {
        // MODE TEST : Accepte tous les logins pour l'instant
        return true;
    }

    private void closeConnection() {
        try {
            if (in != null) in.close();
            if (out != null) out.close();
            if (clientSocket != null) clientSocket.close();
        } catch (IOException e) {

        }
    }
}