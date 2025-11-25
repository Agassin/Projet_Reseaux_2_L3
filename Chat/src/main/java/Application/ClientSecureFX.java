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

    // Champs de classe pour l'état de la connexion
    private final SecurityContextFX securityContext = new SecurityContextFX();
    private PrivateKey clientPrivateKey;
    private PublicKey serverPublicKey;
    private SecretKeySpec aesKeySpec;
    private PrintWriter out;
    private BufferedReader in;

    // Constructeur : gère la connexion et le Handshake (phase bloquante)
    public ClientSecureFX(String host, int port) throws Exception {
        Socket socket = new Socket(host, port);
        this.in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        this.out = new PrintWriter(socket.getOutputStream(), true);

        // === ÉTAPE 1: Échange de clés publiques RSA ===
        String serverPubKeyB64 = in.readLine();
        if (serverPubKeyB64 == null) throw new SecurityException("Clé publique serveur manquante");
        byte[] serverPubKeyBytes = Base64.getDecoder().decode(serverPubKeyB64);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(serverPubKeyBytes);
        this.serverPublicKey = kf.generatePublic(keySpec);

        // Génération et envoi de la clé publique du client
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair clientKeyPair = kpg.generateKeyPair();
        this.clientPrivateKey = clientKeyPair.getPrivate();
        PublicKey clientPublicKey = clientKeyPair.getPublic();
        String clientPubKeyB64 = Base64.getEncoder().encodeToString(clientPublicKey.getEncoded());
        out.println(clientPubKeyB64);

        // === ÉTAPE 2: Échange de clé AES sécurisé ===
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        SecretKey aesKey = kg.generateKey();
        byte[] aesKeyBytes = aesKey.getEncoded();
        this.aesKeySpec = new SecretKeySpec(aesKeyBytes, "AES");

        // Chiffrement de la clé AES avec la clé publique du serveur
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
        byte[] encryptedAesKey = rsaCipher.doFinal(aesKeyBytes);
        String encryptedAesKeyB64 = Base64.getEncoder().encodeToString(encryptedAesKey);
        out.println(encryptedAesKeyB64);

        // === ÉTAPE 3: Confirmation de sécurité ===
        String serverConfirmEncrypted = in.readLine();
        CryptoUtilsFX.verifyAndDecrypt(serverConfirmEncrypted, serverPublicKey, aesKeySpec, securityContext);
    }

    // Méthode pour envoyer un message (appelée par le contrôleur)
    public void sendSecuredMessage(String rawMessage) throws Exception {
        String securedMsg = securityContext.addSecurityHeaders(rawMessage);
        String encryptedMsg = CryptoUtilsFX.signAndEncrypt(securedMsg, clientPrivateKey, aesKeySpec);
        out.println(encryptedMsg);
    }

    // Méthode pour lancer la lecture des messages dans un thread séparé
    public void startListening(ClientController controller) {
        new Thread(() -> {
            try {
                String serverResponse;
                while ((serverResponse = in.readLine()) != null) {
                    String decryptedResponse = CryptoUtilsFX.verifyAndDecrypt(serverResponse, serverPublicKey, aesKeySpec, securityContext);

                    // Mise à jour de la GUI via le contrôleur (essentiel)
                    controller.displayMessage("Serveur > " + decryptedResponse);

                    if (decryptedResponse.equalsIgnoreCase("bye")) {
                        break;
                    }
                }
            } catch (Exception e) {
                controller.displayMessage("Connexion perdue : " + e.getMessage());
            }
            controller.displayMessage("Connexion avec le serveur fermée.");
        }).start();
    }
}