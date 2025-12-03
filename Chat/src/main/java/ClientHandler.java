import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.Cipher;
import javax.crypto.spec.*;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

// Chaque instance de cette classe gère un client dans un thread séparé.
public class ClientHandler implements Runnable {
    private final Socket clientSocket;
    private final SecurityContext securityContext = new SecurityContext();

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
            out.flush();
        } catch (Exception e) {
            System.out.println("❌ Erreur lors de l'envoi broadcast à " + clientName + ": " + e.getMessage());
        }
    }


    @Override
    public void run() {
        try {
            // 1. Initialisation des streams
            in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            out = new PrintWriter(clientSocket.getOutputStream(), true);

            // 2. Handshake
            performHandshake();

            // 3. Boucle de réception de messages
            String encryptedClientMessage;
            while ((encryptedClientMessage = in.readLine()) != null) {
                try {
                    // Vérification, décryptage, vérification des headers de sécurité (sequence, timestamp)
                    String decryptedMessageWithHeaders = CryptoUtils.verifyAndDecrypt(
                            encryptedClientMessage, clientPublicKey, aesKeySpec, securityContext
                    );

                    // CORRECTION: CryptoUtils.verifyAndDecrypt() retourne déjà le message sans les headers.
                    String message = decryptedMessageWithHeaders;

                    System.out.println("💬 Reçu (clair) de " + clientName + ": " + message);

                    // Traitement du message
                    if (message.startsWith("/LOGIN:")) {
                        handleLogin(message);
                    } else if (authenticated) {
                        // Diffuser le message aux autres clients
                        Serveur.broadcast(clientName + " : " + message, this);

                        if (message.toLowerCase().contains("bye") || message.toLowerCase().contains("au revoir")) {
                            sendMessage("Au revoir " + clientName + " !");
                            break;
                        }

                    } else {
                        System.out.println("❌ Message ignoré (non authentifié) : " + message);
                    }

                } catch (SecurityException e) {
                    System.out.println("🚨 [ALERTE SÉCU] Message rejeté de " + clientName + " : " + e.getMessage());
                    break;
                } catch (Exception e) {
                    System.err.println("❌ Erreur inattendue pour " + clientName + ": " + e.getMessage());
                    e.printStackTrace();
                    break;
                }
            }

        } catch (SocketException e) {
            System.out.println("ℹ️ Connexion fermée pour " + clientName + ".");
        } catch (IOException e) {
            System.out.println("ℹ️ Connexion perdue pour " + clientName + ": " + e.getMessage());
        } catch (Exception e) {
            System.err.println("❌ Erreur fatale dans ClientHandler pour " + clientName + ": " + e.getMessage());
        } finally {
            closeConnection();
            // On retire le client s'il a été authentifié
            if (authenticated) {
                Serveur.removeClient(this, clientName);
            }
        }
    }

    private void performHandshake() throws Exception {
        // 1. Générer la paire de clés RSA du serveur
        KeyPair serverKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        serverPrivateKey = serverKeyPair.getPrivate();
        PublicKey serverPublicKey = serverKeyPair.getPublic();

        // 2. Envoyer la clé publique du serveur (B64)
        String serverPubKeyB64 = Base64.getEncoder().encodeToString(serverPublicKey.getEncoded());
        out.println(serverPubKeyB64);
        out.flush();
        System.out.println("❓ [HANDSHAKE] Début avec " + clientSocket.getRemoteSocketAddress());

        // 3. Recevoir la clé publique du client
        String clientPubKeyB64 = in.readLine();
        if (clientPubKeyB64 == null) throw new SecurityException("Clé publique client manquante");
        byte[] clientPubKeyBytes = Base64.getDecoder().decode(clientPubKeyB64);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        clientPublicKey = kf.generatePublic(new X509EncodedKeySpec(clientPubKeyBytes));
        System.out.println("✅ [HANDSHAKE] Clé publique client reçue");

        // 4. Recevoir la clé AES chiffrée
        String encryptedAESKeyB64 = in.readLine();
        if (encryptedAESKeyB64 == null) throw new SecurityException("Clé AES chiffrée manquante");
        byte[] encryptedAESKeyBytes = Base64.getDecoder().decode(encryptedAESKeyB64);

        // Déchiffrer la clé AES avec la clé privée du serveur
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.DECRYPT_MODE, serverPrivateKey);
        byte[] aesKeyBytes = rsaCipher.doFinal(encryptedAESKeyBytes);
        aesKeySpec = new SecretKeySpec(aesKeyBytes, "AES");
        System.out.println("✅ [HANDSHAKE] Clé AES reçue et décryptée");


        // 5. Confirmation de l'établissement de la sécurité
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
            // ⭐ AJOUT : Ajouter le client à la liste de diffusion seulement après succès
            Serveur.addClient(this);

            System.out.println("✅ [AUTH] Authentification RÉUSSIE pour: " + username);
            sendAuthResponse(true, "Bienvenue " + username);
            // Informer les autres clients que ce client a rejoint (si Serveur.broadcast est implémenté)
            Serveur.broadcast(username + " a rejoint le chat.", this);

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
            // Ignorer
        }
    }
}