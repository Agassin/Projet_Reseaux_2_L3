import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

public class ServeurSecure {
    public static final int PORT = 5000;
    private static SecurityContext securityContext = new SecurityContext();

    public static void main(String[] args) {
        // Vérification des fichiers de sécurité
        if (!new File("server.p12").exists() || !new File("truststore.jks").exists()) {
            System.out.println(" Fichiers de sécurité manquants!");
            System.out.println("Veuillez générer les certificats avec les commandes dans le rapport.");
            return;
        }

        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("️  Serveur sécurisé amélioré en attente sur le port " + PORT + "...");
            System.out.println(" Authentification par certificat activée");
            System.out.println(" Signature des messages activée");
            System.out.println(" Protection anti-replay activée");

            while (true) {
                try (Socket clientSocket = serverSocket.accept()) {
                    System.out.println("\n Client connecté : " + clientSocket.getRemoteSocketAddress());
                    traiterClient(clientSocket);
                } catch (Exception e) {
                    System.out.println(" Erreur avec le client: " + e.getMessage());
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void traiterClient(Socket clientSocket) {
        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);

            // === ÉTAPE 1: Chargement du certificat serveur ===
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(new FileInputStream("server.p12"), "password".toCharArray());
            PrivateKey privateKey = (PrivateKey) ks.getKey("server", "password".toCharArray());
            Certificate cert = ks.getCertificate("server");
            PublicKey publicKey = cert.getPublicKey();

            // Envoi du certificat au client
            String certB64 = Base64.getEncoder().encodeToString(cert.getEncoded());
            out.println(certB64);
            System.out.println(" Certificat serveur envoyé au client");

            // === ÉTAPE 2: Réception et vérification du certificat client ===
            String clientCertB64 = in.readLine();
            if (clientCertB64 == null) throw new SecurityException("Certificat client manquant");

            byte[] clientCertBytes = Base64.getDecoder().decode(clientCertB64);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate clientCert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(clientCertBytes));

            // Vérification avec le truststore
            KeyStore trustStore = KeyStore.getInstance("JKS");
            trustStore.load(new FileInputStream("truststore.jks"), "trustpass".toCharArray());
            Certificate caCert = trustStore.getCertificate("myca");
            clientCert.verify(caCert.getPublicKey());
            clientCert.checkValidity();

            PublicKey clientPublicKey = clientCert.getPublicKey();
            System.out.println("Certificat client validé: " + clientCert.getSubjectDN());

            // === ÉTAPE 3: Échange de clé AES sécurisé ===
            String encryptedAesKeyB64 = in.readLine();
            if (encryptedAesKeyB64 == null) throw new SecurityException("Clé AES manquante");

            byte[] encryptedAesKey = Base64.getDecoder().decode(encryptedAesKeyB64);
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] aesKeyBytes = rsaCipher.doFinal(encryptedAesKey);
            SecretKeySpec aesKey = new SecretKeySpec(aesKeyBytes, "AES");
            System.out.println(" Clé AES échangée sécurisée (128 bits)");

            // === ÉTAPE 4: Confirmation de l'établissement de la sécurit� ===
            String secureConfirm = securityContext.addSecurityHeaders("SECURE-HANDSHAKE-OK");
            String encryptedConfirm = signAndEncrypt(secureConfirm, privateKey, aesKey);
            out.println(encryptedConfirm);
            System.out.println(" Poignée de main sécurisée terminée");

            // === ÉTAPE 5: Communication sécurisée ===
            String line;
            while ((line = in.readLine()) != null) {
                try {
                    // Vérification de la signature et décryptage
                    String decrypted = verifyAndDecrypt(line, clientPublicKey, aesKey);

                    System.out.println(" Reçu (chiffré) : " + line.substring(line.lastIndexOf(":") + 1));
                    System.out.println(" Reçu (clair)   : " + decrypted);

                    if (decrypted.equalsIgnoreCase("bye")) {
                        String reply = securityContext.addSecurityHeaders("Au revoir !");
                        String encryptedReply = signAndEncrypt(reply, privateKey, aesKey);
                        out.println(encryptedReply);
                        System.out.println(" Connexion fermée par demande 'bye'");
                        break;
                    }

                    // Réponse écho sécurisée
                    String reply = securityContext.addSecurityHeaders("Serveur a reçu: " + decrypted);
                    String encryptedReply = signAndEncrypt(reply, privateKey, aesKey);
                    out.println(encryptedReply);
                    System.out.println(" Envoyé (clair)  : " + reply);

                } catch (SecurityException e) {
                    System.out.println(" Message rejeté pour raison de sécurité: " + e.getMessage());
                    String errorMsg = securityContext.addSecurityHeaders("ERROR: Security violation");
                    String encryptedError = signAndEncrypt(errorMsg, privateKey, aesKey);
                    out.println(encryptedError);
                }
            }

            in.close();
            out.close();
            System.out.println(" Connexion fermée sécuritairement");

        } catch (Exception e) {
            System.out.println(" Erreur de sécurité: " + e.getMessage());
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

// Classe pour la gestion du contexte de sécurité
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