import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Base64;

// Chaque instance de cette classe gère un client dans un thread séparé.
public class ClientHandler implements Runnable {
    private Socket clientSocket;
    private SecurityContext securityContext = new SecurityContext();

    public ClientHandler(Socket socket) {
        this.clientSocket = socket;
    }

    @Override
    public void run() {
        // La méthode run contient maintenant l'intégralité du traitement pour ce client
        try (
                BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
        ) {
            System.out.println("\n [Thread " + Thread.currentThread().getId() + "] Client connecté: " + clientSocket.getRemoteSocketAddress());

            // === ÉTAPE 1: Génération des clés RSA du serveur ===
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();
            PrivateKey serverPrivateKey = kp.getPrivate();
            PublicKey serverPublicKey = kp.getPublic();

            // Envoi de la clé publique au client
            String pubKeyB64 = Base64.getEncoder().encodeToString(serverPublicKey.getEncoded());
            out.println(pubKeyB64);
            System.out.println(" Clé publique RSA serveur envoyée");

            // === ÉTAPE 2: Réception de la clé publique du client ===
            String clientPubKeyB64 = in.readLine();
            if (clientPubKeyB64 == null) throw new SecurityException("Clé publique client manquante");

            byte[] clientPubKeyBytes = Base64.getDecoder().decode(clientPubKeyB64);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(clientPubKeyBytes);
            PublicKey clientPublicKey = kf.generatePublic(keySpec);
            System.out.println(" Clé publique client reçue et validée");

            // === ÉTAPE 3: Échange de clé AES sécurisé ===
            String encryptedAesKeyB64 = in.readLine();
            if (encryptedAesKeyB64 == null) throw new SecurityException("Clé AES manquante");

            byte[] encryptedAesKey = Base64.getDecoder().decode(encryptedAesKeyB64);
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, serverPrivateKey);
            byte[] aesKeyBytes = rsaCipher.doFinal(encryptedAesKey);
            SecretKeySpec aesKey = new SecretKeySpec(aesKeyBytes, "AES");
            System.out.println(" Clé AES échangée sécurisée (128 bits)");

            // === ÉTAPE 4: Confirmation de l'établissement de la sécurité ===
            String secureConfirm = securityContext.addSecurityHeaders("SECURE-HANDSHAKE-OK");
            String encryptedConfirm = CryptoUtils.signAndEncrypt(secureConfirm, serverPrivateKey, aesKey);
            out.println(encryptedConfirm);
            System.out.println(" Poignée de main sécurisée terminée");

            // === ÉTAPE 5: Communication sécurisée ===
            String line;
            while ((line = in.readLine()) != null) {
                try {
                    // Utilisation des méthodes statiques de CryptoUtils
                    String decrypted = CryptoUtils.verifyAndDecrypt(line, clientPublicKey, aesKey, securityContext);

                    System.out.println(" Reçu (clair)   : " + decrypted);

                    if (decrypted.equalsIgnoreCase("bye")) {
                        String reply = securityContext.addSecurityHeaders("Au revoir !");
                        String encryptedReply = CryptoUtils.signAndEncrypt(reply, serverPrivateKey, aesKey);
                        out.println(encryptedReply);
                        System.out.println(" Connexion fermée par demande 'bye'");
                        break;
                    }

                    // Réponse écho sécurisée
                    String reply = securityContext.addSecurityHeaders("Serveur a reçu: " + decrypted);
                    String encryptedReply = CryptoUtils.signAndEncrypt(reply, serverPrivateKey, aesKey);
                    out.println(encryptedReply);
                    System.out.println(" Envoyé (clair)  : " + reply);

                } catch (SecurityException e) {
                    System.out.println(" Message rejeté pour raison de sécurité: " + e.getMessage());
                    String errorMsg = securityContext.addSecurityHeaders("ERROR: Security violation");
                    String encryptedError = CryptoUtils.signAndEncrypt(errorMsg, serverPrivateKey, aesKey);
                    out.println(encryptedError);
                }
            }

            System.out.println(" [Thread " + Thread.currentThread().getId() + "] Connexion fermée");

        } catch (Exception e) {
            System.out.println(" [Thread " + Thread.currentThread().getId() + "] Erreur: " + e.getMessage());
        } finally {
            try { if (clientSocket != null) clientSocket.close(); } catch (IOException e) {}
        }
    }
}
