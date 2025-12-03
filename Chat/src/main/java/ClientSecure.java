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
    private static SecurityContext securityContext = new SecurityContext();

    public static void main(String[] args) {
        try (Socket socket = new Socket(SERVER_HOST, SERVER_PORT);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             Scanner sc = new Scanner(System.in)) {

            System.out.println(" Connecté au serveur " + SERVER_HOST + ":" + SERVER_PORT);
            System.out.print(" Entrez votre nom d'utilisateur: ");
            String username = sc.nextLine();

            // --- ÉTAPE 1: Poignée de main de sécurité (Handshake) ---

            // Réception de la clé publique du serveur
            String serverPubKeyB64 = in.readLine();
            if (serverPubKeyB64 == null) throw new SecurityException("Clé publique serveur manquante");
            byte[] serverPubKeyBytes = Base64.getDecoder().decode(serverPubKeyB64);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(serverPubKeyBytes);
            PublicKey serverPublicKey = kf.generatePublic(keySpec);

            // Génération et envoi de la clé publique du client
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair clientKeyPair = kpg.generateKeyPair();
            PrivateKey clientPrivateKey = clientKeyPair.getPrivate();
            String clientPubKeyB64 = Base64.getEncoder().encodeToString(clientKeyPair.getPublic().getEncoded());
            out.println(clientPubKeyB64);

            // Échange de clé AES sécurisé
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(128);
            SecretKey aesKey = kg.generateKey();
            SecretKeySpec aesKeySpec = new SecretKeySpec(aesKey.getEncoded(), "AES");

            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
            byte[] encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());
            String encryptedAesKeyB64 = Base64.getEncoder().encodeToString(encryptedAesKey);
            out.println(encryptedAesKeyB64);

            // Confirmation de sécurité
            String serverConfirmEncrypted = in.readLine();
            String serverConfirm = CryptoUtils.verifyAndDecrypt(serverConfirmEncrypted, serverPublicKey, aesKeySpec, securityContext);
            System.out.println(" Poignée de main confirmée par le serveur: " + serverConfirm);

            // === NOUVEAU: Lancement du Thread d'Écoute (Reader) ===
            Thread readerThread = new Thread(new ServerReader(socket, in, serverPublicKey, aesKeySpec, securityContext));
            readerThread.start();

            System.out.println("\n Chat sécurisé prêt. Tapez 'bye' pour quitter.");

            // --- Étape d'identification ---
            // Le serveur attend le format /LOGIN:username:password (bien que 'password' soit ignoré pour l'instant)
            String password = "password_bidon"; // Simuler un mot de passe
            String identificationMsg = "/LOGIN:" + username + ":" + password; // <--- NOUVEAU FORMAT

            String securedIdMsg = securityContext.addSecurityHeaders(identificationMsg);
            String encryptedIdMsg = CryptoUtils.signAndEncrypt(securedIdMsg, clientPrivateKey, aesKeySpec);
            out.println(encryptedIdMsg);

            // Attendre la réponse d'authentification du serveur (AUTH_OK ou AUTH_FAIL)
            String authResponseEncrypted = in.readLine();
            String authResponse = CryptoUtils.verifyAndDecrypt(authResponseEncrypted, serverPublicKey, aesKeySpec, securityContext);
            System.out.println(" [AUTH] Réponse du serveur: " + authResponse);

            if (authResponse.startsWith("AUTH_FAIL")) {
                throw new SecurityException("Authentification échouée: " + authResponse.split(":")[1]);
            }


            // --- ÉTAPE 2: Communication sécurisée (Thread principal pour l'écriture) ---
            while (true) {
                System.out.print(" " + username + " > ");
                String msg = sc.nextLine();

                try {
                    String securedMsg = securityContext.addSecurityHeaders(msg);
                    String encryptedMsg = CryptoUtils.signAndEncrypt(securedMsg, clientPrivateKey, aesKeySpec);

                    out.println(encryptedMsg);

                    if (msg.equalsIgnoreCase("bye")) {
                        break;
                    }

                } catch (Exception e) {
                    System.out.println(" Erreur lors de l'envoi du message: " + e.getMessage());
                }
            }

            System.out.println(" Déconnexion demandée...");
            // Le socket sera fermé par le bloc try-with-resources
            readerThread.interrupt(); // Force l'arrêt du thread d'écoute

        } catch (Exception e) {
            System.out.println(" Erreur fatale du client: " + e.getMessage());
        }
    }
}