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

    public ClientHandler(Socket socket) {
        this.clientSocket = socket;
    }

    // Méthode publique appelée par Serveur.broadcast()
    public void sendMessage(String plainMessage) {
        try {
            String securedMessage = securityContext.addSecurityHeaders(plainMessage);
            String encryptedReply = CryptoUtils.signAndEncrypt(securedMessage, serverPrivateKey, aesKeySpec);
            out.println(encryptedReply);
        } catch (Exception e) {
            System.out.println(" Erreur lors de l'envoi broadcast à " + clientName + ": " + e.getMessage());
        }
    }

    @Override
    public void run() {
        BufferedReader in = null;
        try {
            in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            this.out = new PrintWriter(clientSocket.getOutputStream(), true);

            // --- ÉTAPE 1: Poignée de main de sécurité (Handshake) ---

            // Génération des clés RSA du serveur
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();
            this.serverPrivateKey = kp.getPrivate();
            PublicKey serverPublicKey = kp.getPublic();

            // Envoi de la clé publique au client
            String pubKeyB64 = Base64.getEncoder().encodeToString(serverPublicKey.getEncoded());
            out.println(pubKeyB64);

            // Réception de la clé publique du client
            String clientPubKeyB64 = in.readLine();
            if (clientPubKeyB64 == null) throw new SecurityException("Clé publique client manquante");

            byte[] clientPubKeyBytes = Base64.getDecoder().decode(clientPubKeyB64);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(clientPubKeyBytes);
            this.clientPublicKey = kf.generatePublic(keySpec);

            // Échange de clé AES sécurisé
            String encryptedAesKeyB64 = in.readLine();
            if (encryptedAesKeyB64 == null) throw new SecurityException("Clé AES manquante");

            byte[] encryptedAesKey = Base64.getDecoder().decode(encryptedAesKeyB64);
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, serverPrivateKey);
            byte[] aesKeyBytes = rsaCipher.doFinal(encryptedAesKey);
            this.aesKeySpec = new SecretKeySpec(aesKeyBytes, "AES");

            // Confirmation de l'établissement de la sécurité
            String secureConfirm = securityContext.addSecurityHeaders("SECURE-HANDSHAKE-OK");
            String encryptedConfirm = CryptoUtils.signAndEncrypt(secureConfirm, serverPrivateKey, aesKeySpec);
            out.println(encryptedConfirm);

            System.out.println(" Poignée de main sécurisée terminée avec " + clientSocket.getRemoteSocketAddress());
            Serveur.addClient(this); // Ajout du client UNIQUEMENT après succès du handshake

            // --- ÉTAPE 2: Communication sécurisée (boucle d'écoute) ---
            String line;
            while ((line = in.readLine()) != null) {
                try {
                    // Vérifie/Décrypte (Utilise les attributs de classe)
                    String decrypted = CryptoUtils.verifyAndDecrypt(line, clientPublicKey, aesKeySpec, securityContext);

                    // Si c'est la première communication, on récupère le nom d'utilisateur (convention simple)
                    if (clientName.equals("Inconnu")) {
                        // On assume que le premier message est le nom d'utilisateur
                        clientName = decrypted.split(":")[0];
                        Serveur.broadcast(clientName + " a rejoint le chat.", this);
                        continue; // Le premier message est juste pour l'identification
                    }

                    System.out.println(" Reçu (clair) de " + clientName + " : " + decrypted);

                    if (decrypted.equalsIgnoreCase("bye")) {
                        sendMessage("Au revoir !");
                        break;
                    }

                    // DIFFUSION DU MESSAGE REÇU
                    String broadcastMessage = clientName + ": " + decrypted;
                    Serveur.broadcast(broadcastMessage, this);

                } catch (SecurityException e) {
                    System.out.println(" Message rejeté de " + clientName + " pour raison de sécurité: " + e.getMessage());
                    sendMessage("ERROR: Security violation");
                }
            }

        } catch (Exception e) {
            System.out.println(" [Thread " + Thread.currentThread().getId() + "] Erreur de connexion/sécurité avec " + clientName + ": " + e.getMessage());
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
}