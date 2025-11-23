import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Base64;
import java.util.Scanner;

public class ClientSecure {
    public static final String SERVER_HOST = "localhost";
    public static final int SERVER_PORT = 5000;
    private static SecurityContext securityContext = new SecurityContext();

    public static void main(String[] args) {
        // Vérification des fichiers de sécurité
        if (!new File("client.p12").exists() || !new File("truststore.jks").exists()) {
            System.out.println(" Fichiers de sécurité manquants!");
            System.out.println("Veuillez générer les certificats avec les commandes dans le rapport.");
            return;
        }

        try (Socket socket = new Socket(SERVER_HOST, SERVER_PORT)) {
            System.out.println(" Connecté au serveur " + SERVER_HOST + ":" + SERVER_PORT);
            System.out.println(" Authentification par certificat activée");
            System.out.println(" Signature des messages activée");
            System.out.println("  Protection anti-replay activée");

            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            Scanner sc = new Scanner(System.in);

            // === ÉTAPE 1: Échange de certificats ===

            // Réception et vérification du certificat serveur
            String serverCertB64 = in.readLine();
            if (serverCertB64 == null) throw new SecurityException("Certificat serveur manquant");

            byte[] serverCertBytes = Base64.getDecoder().decode(serverCertB64);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate serverCert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(serverCertBytes));

            // Vérification avec le truststore
            KeyStore trustStore = KeyStore.getInstance("JKS");
            trustStore.load(new FileInputStream("truststore.jks"), "trustpass".toCharArray());
            Certificate caCert = trustStore.getCertificate("myca");
            serverCert.verify(caCert.getPublicKey());
            serverCert.checkValidity();

            PublicKey serverPublicKey = serverCert.getPublicKey();
            System.out.println(" Certificat serveur validé: " + serverCert.getSubjectDN());

            // Envoi du certificat client
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(new FileInputStream("client.p12"), "password".toCharArray());
            Certificate clientCert = ks.getCertificate("client");
            String clientCertB64 = Base64.getEncoder().encodeToString(clientCert.getEncoded());
            out.println(clientCertB64);
            System.out.println(" Certificat client envoyé au serveur");

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
            System.out.println(" c bon " + serverConfirm);

            // === ÉTAPE 4: Communication sécurisée ===
            while (true) {
                System.out.print("\n Vous > ");
                String msg = sc.nextLine();

                try {
                    String securedMsg = securityContext.addSecurityHeaders(msg);
                    String encryptedMsg = signAndEncrypt(securedMsg,
                            (PrivateKey) ks.getKey("client", "password".toCharArray()), aesKeySpec);

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