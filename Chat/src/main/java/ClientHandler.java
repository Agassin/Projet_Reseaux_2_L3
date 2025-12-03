import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.Cipher;
import javax.crypto.spec.*;
import java.util.Base64;

// Chaque instance de cette classe gère un client dans un thread séparé.
public class ClientHandler implements Runnable {
    private Socket clientSocket;
    private SecurityContext securityContext = new SecurityContext();

    // Attributs pour la communication sécurisée avec ce client spécifique
    private PrivateKey serverPrivateKey;
    private PublicKey clientPublicKey;
    private SecretKeySpec aesKeySpec;
    private PrintWriter out;

    private String clientName = "Inconnu";
    private boolean authenticated = false; // ⭐ NOUVEAU : Flag d'authentification

    public ClientHandler(Socket socket) {
        this.clientSocket = socket;
    }

    // Méthode publique appelée par Serveur.broadcast()
    public void sendMessage(String plainMessage) {
        try {
            String securedMessage = securityContext.addSecurityHeaders(plainMessage);
            String encryptedReply = CryptoUtils.signAndEncrypt(securedMessage, serverPrivateKey, aesKeySpec);
            out.println(encryptedReply);
            out.flush(); // ⭐ IMPORTANT : Forcer l'envoi
        } catch (Exception e) {
            System.out.println("❌ Erreur lors de l'envoi broadcast à " + clientName + ": " + e.getMessage());
        }
    }

    @Override
    public void run() {
        BufferedReader in = null;
        try {
            in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            this.out = new PrintWriter(clientSocket.getOutputStream(), true);

            // --- ÉTAPE 1: Poignée de main de sécurité (Handshake) ---
            System.out.println("🔐 [HANDSHAKE] Début avec " + clientSocket.getRemoteSocketAddress());

            // Génération des clés RSA du serveur
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();
            this.serverPrivateKey = kp.getPrivate();
            PublicKey serverPublicKey = kp.getPublic();

            // Envoi de la clé publique au client
            String pubKeyB64 = Base64.getEncoder().encodeToString(serverPublicKey.getEncoded());
            out.println(pubKeyB64);
            System.out.println("📤 [HANDSHAKE] Clé publique serveur envoyée");

            // Réception de la clé publique du client
            String clientPubKeyB64 = in.readLine();
            if (clientPubKeyB64 == null) throw new SecurityException("Clé publique client manquante");

            byte[] clientPubKeyBytes = Base64.getDecoder().decode(clientPubKeyB64);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(clientPubKeyBytes);
            this.clientPublicKey = kf.generatePublic(keySpec);
            System.out.println("📥 [HANDSHAKE] Clé publique client reçue");

            // Échange de clé AES sécurisé
            String encryptedAesKeyB64 = in.readLine();
            if (encryptedAesKeyB64 == null) throw new SecurityException("Clé AES manquante");

            byte[] encryptedAesKey = Base64.getDecoder().decode(encryptedAesKeyB64);
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, serverPrivateKey);
            byte[] aesKeyBytes = rsaCipher.doFinal(encryptedAesKey);
            this.aesKeySpec = new SecretKeySpec(aesKeyBytes, "AES");
            System.out.println("🔑 [HANDSHAKE] Clé AES déchiffrée");

            // Confirmation de l'établissement de la sécurité
            String secureConfirm = securityContext.addSecurityHeaders("SECURE-HANDSHAKE-OK");
            String encryptedConfirm = CryptoUtils.signAndEncrypt(secureConfirm, serverPrivateKey, aesKeySpec);
            out.println(encryptedConfirm);
            out.flush();

            System.out.println("✅ [HANDSHAKE] Poignée de main sécurisée terminée avec " + clientSocket.getRemoteSocketAddress());

            // --- ⭐ ÉTAPE 2: AUTHENTIFICATION (NOUVEAU) ---
            System.out.println("🔐 [AUTH] Attente des credentials...");

            String authLine = in.readLine();
            if (authLine == null) {
                System.err.println("❌ [AUTH] Client déconnecté avant authentification");
                return;
            }

            // Décrypter le message d'authentification
            String decryptedAuth = CryptoUtils.verifyAndDecrypt(authLine, clientPublicKey, aesKeySpec, securityContext);
            System.out.println("📥 [AUTH] Message reçu: " + decryptedAuth);

            // Vérifier que c'est bien un message de login
            if (!decryptedAuth.startsWith("/LOGIN:")) {
                System.err.println("❌ [AUTH] Format invalide (attendu /LOGIN:) : " + decryptedAuth);
                sendAuthResponse(false, "Format d'authentification invalide");
                return;
            }

            // Traiter l'authentification
            handleLogin(decryptedAuth);

            // Si l'authentification a échoué, on arrête ici
            if (!authenticated) {
                System.out.println("❌ [AUTH] Authentification échouée, fermeture connexion");
                return;
            }

            // ⭐ AJOUT DU CLIENT UNIQUEMENT APRÈS AUTHENTIFICATION RÉUSSIE
            Serveur.addClient(this);
            System.out.println("✅ [AUTH] Client " + clientName + " authentifié et ajouté au serveur");

            // Notifier les autres utilisateurs
            Serveur.broadcast(clientName + " a rejoint le chat.", this);

            // --- ÉTAPE 3: Communication sécurisée (boucle d'écoute) ---
            String line;
            while ((line = in.readLine()) != null) {
                try {
                    // Vérifie/Décrypte
                    String decrypted = CryptoUtils.verifyAndDecrypt(line, clientPublicKey, aesKeySpec, securityContext);

                    System.out.println("💬 Reçu (clair) de " + clientName + " : " + decrypted);

                    // Gestion des commandes spéciales
                    if (decrypted.toLowerCase().contains("bye") ||
                            decrypted.toLowerCase().contains("au revoir")) {
                        sendMessage("Au revoir " + clientName + " !");
                        break;
                    }

                    // DIFFUSION DU MESSAGE REÇU
                    Serveur.broadcast(decrypted, this);

                } catch (SecurityException e) {
                    System.out.println("⚠️ Message rejeté de " + clientName + " pour raison de sécurité: " + e.getMessage());
                    sendMessage("ERROR: Security violation");
                }
            }

        } catch (Exception e) {
            System.out.println("❌ [Thread " + Thread.currentThread().getId() + "] Erreur avec " + clientName + ": " + e.getMessage());
            e.printStackTrace();
        } finally {
            try {
                if (in != null) in.close();
                if (out != null) out.close();
                if (clientSocket != null) clientSocket.close();
            } catch (IOException e) {}

            // RETIRER LE CLIENT
            Serveur.removeClient(this, clientName);
        }
    }

    // ⭐ NOUVELLE MÉTHODE : Gérer l'authentification
    private void handleLogin(String loginMessage) {
        try {
            // Format attendu: /LOGIN:username:password
            String[] parts = loginMessage.split(":", 3);

            if (parts.length < 3) {
                System.err.println("❌ [AUTH] Format invalide, parties reçues: " + parts.length);
                sendAuthResponse(false, "Format de login invalide");
                return;
            }

            String username = parts[1].trim();
            String password = parts[2].trim();

            System.out.println("🔐 [AUTH] Tentative - Username: " + username + ", Password: ***");

            // ⭐ Validation des credentials
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

        } catch (Exception e) {
            System.err.println("❌ [AUTH] Erreur lors de l'authentification: " + e.getMessage());
            e.printStackTrace();
            try {
                sendAuthResponse(false, "Erreur serveur lors de l'authentification");
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }
    }

    // ⭐ NOUVELLE MÉTHODE : Envoyer la réponse d'authentification
    private void sendAuthResponse(boolean success, String message) throws Exception {
        String response = success ? "AUTH_OK: " + message : "AUTH_FAIL: " + message;

        System.out.println("📤 [AUTH] Envoi réponse: " + response);

        // Sécuriser le message (ajouter headers, signer, chiffrer)
        String securedMsg = securityContext.addSecurityHeaders(response);
        String encryptedMsg = CryptoUtils.signAndEncrypt(securedMsg, serverPrivateKey, aesKeySpec);

        out.println(encryptedMsg);
        out.flush(); // ⚠️ CRITIQUE : Forcer l'envoi immédiat

        System.out.println("✅ [AUTH] Réponse envoyée et flushée");
    }

    // ⭐ NOUVELLE MÉTHODE : Valider les credentials
    private boolean authenticateUser(String username, String password) {
        // ⭐ MODE TEST : Accepter tous les logins
        System.out.println("ℹ️ [AUTH] Mode test : tous les logins sont acceptés");
        return true;

        // OPTION 2 : Credentials en dur (décommentez pour tester)
        /*
        if (username.equals("admin") && password.equals("1234")) return true;
        if (username.equals("alice") && password.equals("password")) return true;
        if (username.equals("bob") && password.equals("secret")) return true;
        return false;
        */

        // OPTION 3 : Base de données (à implémenter plus tard)
        // return UserDatabase.checkCredentials(username, password);
    }
}