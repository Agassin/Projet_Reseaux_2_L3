import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Base64;
import java.util.HashSet;
import java.util.Scanner;
import java.util.Set;

public class ClientSecure {
    public static final String SERVER_HOST = "localhost";
    public static final int SERVER_PORT = 5000;
    private static SecurityContext securityContext = new SecurityContext();

    public static void main(String[] args) {
        try (Socket socket = new Socket(SERVER_HOST, SERVER_PORT)) {
            System.out.println(" Connecté au serveur " + SERVER_HOST + ":" + SERVER_PORT);
            System.out.println(" Authentification par clés RSA activée");
            System.out.println(" Signature des messages activée");
            System.out.println(" Protection anti-replay activée");

            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            Scanner sc = new Scanner(System.in);

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
            String serverConfirm = verifyAndDecrypt(serverConfirmEncrypted, serverPublicKey, aesKeySpec);
            System.out.println("c bon " + serverConfirm);

            // === ÉTAPE 4: Communication sécurisée ===
            while (true) {
                System.out.print("\n Vous > ");
                String msg = sc.nextLine();

                try {
                    String securedMsg = securityContext.addSecurityHeaders(msg);
                    String encryptedMsg = signAndEncrypt(securedMsg, clientPrivateKey, aesKeySpec);

                    out.println(encryptedMsg);
                    System.out.println(" Envoyé (clair)  : " + msg);

                    if (msg.equalsIgnoreCase("bye")) {
                        System.out.println(" Déconnexion demandée");
                        break;
                    }

                    // Réception de la réponse
                    String serverResponse = in.readLine();
                    if (serverResponse == null) break;

                    String decryptedResponse = verifyAndDecrypt(serverResponse, serverPublicKey, aesKeySpec);
                    System.out.println(" Serveur > " + decryptedResponse);

                } catch (SecurityException e) {
                    System.out.println(" Erreur de sécurité: " + e.getMessage());
                }
            }

            in.close();
            out.close();
            sc.close();
            System.out.println(" Connexion fermée");

        } catch (Exception e) {
            System.out.println(" Erreur: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static String signAndEncrypt(String plain, PrivateKey privateKey, SecretKeySpec aesKey) throws Exception {
        // Signature du message
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(plain.getBytes("UTF-8"));
        byte[] digitalSignature = signature.sign();

        // Combinaison message + signature
        String messageWithSig = plain + "|SIG|" + Base64.getEncoder().encodeToString(digitalSignature);

        // Chiffrement AES
        return encryptAndEncode(messageWithSig, aesKey);
    }

    private static String verifyAndDecrypt(String encrypted, PublicKey publicKey, SecretKeySpec aesKey) throws Exception {
        // Décryptage AES
        String decryptedWithSig = decryptAndDecode(encrypted, aesKey);

        // Séparation message et signature
        String[] parts = decryptedWithSig.split("\\|SIG\\|");
        if (parts.length != 2) {
            throw new SecurityException("Signature manquante");
        }

        String message = parts[0];
        byte[] signature = Base64.getDecoder().decode(parts[1]);

        // Vérification de la signature
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(message.getBytes("UTF-8"));

        if (!sig.verify(signature)) {
            throw new SecurityException("Signature invalide");
        }

        // Vérification des en-têtes de sécurité
        return securityContext.verifySecurityHeaders(message);
    }

    private static String encryptAndEncode(String plain, SecretKeySpec aesKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecureRandom rnd = new SecureRandom();
        byte[] iv = new byte[16];
        rnd.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
        byte[] ct = cipher.doFinal(plain.getBytes("UTF-8"));
        String ivB64 = Base64.getEncoder().encodeToString(iv);
        String ctB64 = Base64.getEncoder().encodeToString(ct);
        return ivB64 + ":" + ctB64;
    }

    private static String decryptAndDecode(String encrypted, SecretKeySpec aesKey) throws Exception {
        String[] parts = encrypted.split(":");
        if (parts.length != 2) throw new IllegalArgumentException("Format chiffré invalide");

        byte[] iv = Base64.getDecoder().decode(parts[0]);
        byte[] cipherBytes = Base64.getDecoder().decode(parts[1]);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
        byte[] plainBytes = cipher.doFinal(cipherBytes);
        return new String(plainBytes, "UTF-8");
    }
}

// Classe pour la gestion du contexte de sécurité (identique au serveur)
class SecurityContext {
    private long lastTimestamp = 0;
    private int sequenceNumber = 0;
    private Set<String> seenMessages = new HashSet<>();

    public synchronized String addSecurityHeaders(String message) {
        long timestamp = System.currentTimeMillis();
        sequenceNumber++;

        String securedMessage = timestamp + "|" + sequenceNumber + "|" + message;

        // Protection contre le replay
        if (seenMessages.contains(securedMessage)) {
            throw new SecurityException("Message rejoué détecté");
        }
        seenMessages.add(securedMessage);

        // Nettoyage périodique
        if (seenMessages.size() > 1000) {
            seenMessages.clear();
        }

        return securedMessage;
    }

    public synchronized String verifySecurityHeaders(String securedMessage) {
        String[] parts = securedMessage.split("\\|", 3);
        if (parts.length != 3) {
            throw new SecurityException("En-têtes de sécurité manquantes");
        }

        long timestamp = Long.parseLong(parts[0]);
        int seq = Integer.parseInt(parts[1]);
        String message = parts[2];

        // Vérification timestamp (5 minutes de tolérance)
        long currentTime = System.currentTimeMillis();
        if (Math.abs(currentTime - timestamp) > 300000) { // 5 minutes
            throw new SecurityException("Message trop ancien");
        }

        // Vérification séquence
        if (seq <= sequenceNumber) {
            throw new SecurityException("Numéro de séquence invalide");
        }
        sequenceNumber = seq;

        return message;
    }
}