import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Base64;
import java.util.Scanner;

public class ClientSecure {
    public static final String SERVER_HOST = "localhost";
    public static final int SERVER_PORT = 5000;
    // Crée une instance locale de SecurityContext pour le client
    private static SecurityContext securityContext = new SecurityContext();

    public static void main(String[] args) {
        try (Socket socket = new Socket(SERVER_HOST, SERVER_PORT);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             Scanner sc = new Scanner(System.in)) {

            System.out.println(" Connecté au serveur " + SERVER_HOST + ":" + SERVER_PORT);

            // === ÉTAPE 1: Échange de clés publiques RSA ===

            // Réception de la clé publique du serveur
            String serverPubKeyB64 = in.readLine();
            if (serverPubKeyB64 == null) throw new SecurityException("Clé publique serveur manquante");

            byte[] serverPubKeyBytes = Base64.getDecoder().decode(serverPubKeyB64);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(serverPubKeyBytes);
            PublicKey serverPublicKey = kf.generatePublic(keySpec);
            System.out.println(" Clé publique serveur reçue et validée");

            // Génération et envoi de la clé publique du client
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair clientKeyPair = kpg.generateKeyPair();
            PrivateKey clientPrivateKey = clientKeyPair.getPrivate();
            PublicKey clientPublicKey = clientKeyPair.getPublic();

            String clientPubKeyB64 = Base64.getEncoder().encodeToString(clientPublicKey.getEncoded());
            out.println(clientPubKeyB64);
            System.out.println(" Clé publique client envoyée au serveur");

            // === ÉTAPE 2: Échange de clé AES sécurisé ===
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(128);
            SecretKey aesKey = kg.generateKey();
            byte[] aesKeyBytes = aesKey.getEncoded();
            SecretKeySpec aesKeySpec = new SecretKeySpec(aesKeyBytes, "AES");

            // Chiffrement de la clé AES avec la clé publique du serveur
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
            byte[] encryptedAesKey = rsaCipher.doFinal(aesKeyBytes);
            String encryptedAesKeyB64 = Base64.getEncoder().encodeToString(encryptedAesKey);
            out.println(encryptedAesKeyB64);
            System.out.println(" Clé AES générée et envoyée (chiffrée avec RSA)");

            // === ÉTAPE 3: Confirmation de sécurité ===
            String serverConfirmEncrypted = in.readLine();
            // Utilisation des méthodes statiques de CryptoUtils
            String serverConfirm = CryptoUtils.verifyAndDecrypt(serverConfirmEncrypted, serverPublicKey, aesKeySpec, securityContext);
            System.out.println(" Poignée de main confirmée par le serveur: " + serverConfirm);

            // === ÉTAPE 4: Communication sécurisée ===
            while (true) {
                System.out.print("\n Vous > ");
                String msg = sc.nextLine();

                try {
                    String securedMsg = securityContext.addSecurityHeaders(msg);
                    // Utilisation des méthodes statiques de CryptoUtils
                    String encryptedMsg = CryptoUtils.signAndEncrypt(securedMsg, clientPrivateKey, aesKeySpec);

                    out.println(encryptedMsg);
                    System.out.println(" Envoyé (clair)  : " + msg);

                    if (msg.equalsIgnoreCase("bye")) {
                        System.out.println(" Déconnexion demandée");
                        break;
                    }

                    // Réception de la réponse
                    String serverResponse = in.readLine();
                    if (serverResponse == null) break;

                    // Utilisation des méthodes statiques de CryptoUtils
                    String decryptedResponse = CryptoUtils.verifyAndDecrypt(serverResponse, serverPublicKey, aesKeySpec, securityContext);
                    System.out.println(" Serveur > " + decryptedResponse);

                } catch (SecurityException e) {
                    System.out.println(" Erreur de sécurité: " + e.getMessage());
                }
            }

            System.out.println(" Connexion fermée");

        } catch (Exception e) {
            System.out.println(" Erreur: " + e.getMessage());
        }
    }
}
