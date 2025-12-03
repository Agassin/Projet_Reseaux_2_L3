package Application;

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Base64;

/**
 * Client sécurisé JavaFX avec chiffrement RSA/AES et authentification.
 * CORRECTION: Utilisation d'une SEULE instance de SecurityContextFX partagée.
 */
public class ClientSecureFX {
    public static final String SERVER_HOST = "localhost";
    public static final int SERVER_PORT = 5000;

    // ⭐ UNE SEULE INSTANCE de SecurityContext (partagée pour tous les messages)
    // CRITIQUE: Ne jamais créer de nouvelles instances avec "new SecurityContextFX()"
    private final SecurityContextFX securityContext = new SecurityContextFX();

    private PrivateKey clientPrivateKey;
    private PublicKey serverPublicKey;
    private SecretKeySpec aesKeySpec;
    private PrintWriter out;
    private BufferedReader in;
    private final String username;
    private Socket socket;

    /**
     * Constructeur: établit la connexion et effectue le handshake de sécurité.
     */
    public ClientSecureFX(String host, int port, String username) throws Exception {
        this.username = username;
        System.out.println("\n========== CONNEXION CLIENT ==========");
        System.out.println("[CLIENT] Connexion à " + host + ":" + port + "...");

        this.socket = new Socket(host, port);
        this.in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        this.out = new PrintWriter(socket.getOutputStream(), true);

        System.out.println("[CLIENT] ✓ Socket connectée");
        performHandshake();
        System.out.println("========== HANDSHAKE TERMINÉ ==========\n");
    }

    /**
     * Effectue l'échange de clés RSA et AES avec le serveur.
     */
    private void performHandshake() throws Exception {
        System.out.println("\n[HANDSHAKE] Début de l'échange de clés...");

        // --- ÉTAPE 1: Réception de la clé publique du serveur ---
        String serverPubKeyB64 = in.readLine();
        if (serverPubKeyB64 == null) {
            throw new SecurityException("Clé publique serveur manquante");
        }

        byte[] serverPubKeyBytes = Base64.getDecoder().decode(serverPubKeyB64);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(serverPubKeyBytes);
        this.serverPublicKey = kf.generatePublic(keySpec);
        System.out.println("[HANDSHAKE] ✓ Clé publique serveur reçue (" + serverPubKeyBytes.length + " bytes)");

        // --- ÉTAPE 2: Génération et envoi de la clé publique client ---
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair clientKeyPair = kpg.generateKeyPair();
        this.clientPrivateKey = clientKeyPair.getPrivate();

        String clientPubKeyB64 = Base64.getEncoder().encodeToString(clientKeyPair.getPublic().getEncoded());
        out.println(clientPubKeyB64);
        System.out.println("[HANDSHAKE] ✓ Clé publique client envoyée");

        // --- ÉTAPE 3: Génération et envoi de la clé AES (chiffrée avec RSA) ---
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        SecretKey aesKey = kg.generateKey();
        this.aesKeySpec = new SecretKeySpec(aesKey.getEncoded(), "AES");

        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
        byte[] encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());
        String encryptedAesKeyB64 = Base64.getEncoder().encodeToString(encryptedAesKey);
        out.println(encryptedAesKeyB64);
        System.out.println("[HANDSHAKE] ✓ Clé AES envoyée (chiffrée)");

        // --- ÉTAPE 4: Confirmation du serveur ---
        String serverConfirmEncrypted = in.readLine();
        if (serverConfirmEncrypted == null) {
            throw new SecurityException("Confirmation serveur manquante");
        }

        // ⭐ IMPORTANT: Utiliser LA MÊME instance securityContext
        String confirm = CryptoUtilsFX.verifyAndDecrypt(
                serverConfirmEncrypted,
                serverPublicKey,
                aesKeySpec,
                securityContext  // ⭐ Pas "new SecurityContextFX()"
        );
        System.out.println("[HANDSHAKE] ✓ Confirmation reçue: " + confirm);
    }

    /**
     * Envoie les credentials et attend la réponse d'authentification (BLOQUANT).
     */
    public void sendLoginCredentials(String username, String password) throws Exception {
        System.out.println("\n[AUTH] Envoi des credentials pour: " + username);

        String loginMessage = "/LOGIN:" + username + ":" + password;

        // Ajout des en-têtes de sécurité + signature + chiffrement
        String securedMsg = securityContext.addSecurityHeaders(loginMessage);
        String encryptedMsg = CryptoUtilsFX.signAndEncrypt(securedMsg, clientPrivateKey, aesKeySpec);
        out.println(encryptedMsg);
        System.out.println("[AUTH] ✓ Message de login envoyé");

        // ⚠️ ATTENTE BLOQUANTE de la réponse AUTH_OK ou AUTH_FAIL
        System.out.println("[AUTH] Attente de la réponse du serveur...");
        String authResponseEncrypted = in.readLine();
        if (authResponseEncrypted == null) {
            throw new SecurityException("Réponse d'authentification manquante (serveur déconnecté?)");
        }

        // ⭐ IMPORTANT: Utiliser LA MÊME instance securityContext
        String decryptedResponse = CryptoUtilsFX.verifyAndDecrypt(
                authResponseEncrypted,
                serverPublicKey,
                aesKeySpec,
                securityContext  // ⭐ Pas "new SecurityContextFX()"
        );

        System.out.println("[AUTH] Réponse reçue: " + decryptedResponse);

        // Vérification du statut
        if (!decryptedResponse.startsWith("AUTH_OK")) {
            String reason = "Raison inconnue";
            if (decryptedResponse.contains(":")) {
                reason = decryptedResponse.substring(decryptedResponse.indexOf(':') + 1).trim();
            }
            throw new SecurityException("Authentification refusée: " + reason);
        }

        System.out.println("[AUTH] ✓ Authentification réussie!\n");
    }

    /**
     * Envoie un message sécurisé au serveur.
     */
    public void sendSecuredMessage(String rawMessage) throws Exception {
        String securedMsg = securityContext.addSecurityHeaders(rawMessage);
        String encryptedMsg = CryptoUtilsFX.signAndEncrypt(securedMsg, clientPrivateKey, aesKeySpec);
        out.println(encryptedMsg);
        System.out.println("[CLIENT] 📤 Message envoyé: " + rawMessage);
    }

    /**
     * Démarre le thread d'écoute des messages du serveur.
     * Met à jour l'interface graphique via le contrôleur.
     */
    public void startListening(ClientController controller) {
        Thread listenerThread = new Thread(() -> {
            System.out.println("\n[CLIENT] 🎧 Thread d'écoute démarré");

            try {
                String serverResponse;
                while ((serverResponse = in.readLine()) != null) {
                    try {
                        // ⭐ IMPORTANT: Utiliser LA MÊME instance securityContext
                        String decryptedResponse = CryptoUtilsFX.verifyAndDecrypt(
                                serverResponse,
                                serverPublicKey,
                                aesKeySpec,
                                securityContext  // ⭐ Pas "new SecurityContextFX()"
                        );

                        System.out.println("[CLIENT] 📥 Message reçu: " + decryptedResponse);

                        // Affichage dans l'interface graphique
                        controller.displayMessage(decryptedResponse);

                    } catch (SecurityException e) {
                        System.err.println("[CLIENT] ❌ Erreur de sécurité: " + e.getMessage());
                        controller.displayMessage("[SÉCURITÉ] " + e.getMessage());
                    } catch (Exception e) {
                        System.err.println("[CLIENT] ❌ Erreur déchiffrement: " + e.getMessage());
                        e.printStackTrace();
                    }
                }
            } catch (IOException e) {
                if (!socket.isClosed()) {
                    System.err.println("[CLIENT] ❌ Erreur lecture: " + e.getMessage());
                    controller.displayMessage("[ERREUR] Connexion perdue: " + e.getMessage());
                }
            }

            System.out.println("[CLIENT] 🔌 Thread d'écoute terminé");
            controller.displayMessage("--- Connexion fermée ---");

        }, "ClientListener");

        listenerThread.setDaemon(true); // Thread daemon pour fermeture propre
        listenerThread.start();
    }

    /**
     * Ferme proprement la connexion avec le serveur.
     */
    public void closeConnection() {
        try {
            if (socket != null && !socket.isClosed()) {
                socket.close();
                System.out.println("[CLIENT] ✓ Connexion fermée");
            }
        } catch (IOException e) {
            System.err.println("[CLIENT] Erreur lors de la fermeture: " + e.getMessage());
        }
    }

    /**
     * Vérifie si la connexion est toujours active.
     */
    public boolean isConnected() {
        return socket != null && !socket.isClosed() && socket.isConnected();
    }
}