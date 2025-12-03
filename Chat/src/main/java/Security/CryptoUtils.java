package Security;

import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Base64;
import java.io.UnsupportedEncodingException;

public class CryptoUtils {

    // --- Fonctions de chiffrement AES (avec IV pour CBC) ---

    public static String encryptAndEncode(String plain, SecretKeySpec aesKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecureRandom rnd = new SecureRandom();
        byte[] iv = new byte[16];
        rnd.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);

        byte[] ct = cipher.doFinal(plain.getBytes("UTF-8"));

        String ivB64 = Base64.getEncoder().encodeToString(iv);
        String ctB64 = Base64.getEncoder().encodeToString(ct);

        // Format: IV:Ciphertext
        return ivB64 + ":" + ctB64;
    }

    public static String decryptAndDecode(String encrypted, SecretKeySpec aesKey) throws Exception {
        String[] parts = encrypted.split(":");
        if (parts.length != 2) throw new IllegalArgumentException("Format chiffré invalide");

        byte[] iv = Base64.getDecoder().decode(parts[0]);
        byte[] cipherBytes = Base64.getDecoder().decode(parts[1]);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);

        byte[] plainBytes = cipher.doFinal(cipherBytes);
        return new String(plainBytes, "UTF-8");
    }

    // --- Fonctions de signature et de chiffrement RSA/AES ---

    public static String signAndEncrypt(String plain, PrivateKey privateKey, SecretKeySpec aesKey) throws Exception {
        // 1. Signature du message clair (avec headers de sécurité)
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(plain.getBytes("UTF-8"));
        byte[] digitalSignature = signature.sign();

        // 2. Combinaison message + signature
        String messageWithSig = plain + "|SIG|" + Base64.getEncoder().encodeToString(digitalSignature);

        // 3. Chiffrement AES de l'ensemble
        return encryptAndEncode(messageWithSig, aesKey);
    }

    public static String verifyAndDecrypt(String encrypted, PublicKey publicKey, SecretKeySpec aesKey, SecurityContext context) throws Exception {
        // 1. Décryptage AES
        String decryptedWithSig = decryptAndDecode(encrypted, aesKey);

        // 2. Séparation message et signature
        String[] parts = decryptedWithSig.split("\\|SIG\\|");
        if (parts.length != 2) {
            throw new SecurityException("Signature manquante ou format de message corrompu");
        }

        String securedMessage = parts[0];
        byte[] signature = Base64.getDecoder().decode(parts[1]);

        // 3. Vérification de la signature
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(securedMessage.getBytes("UTF-8"));

        if (!sig.verify(signature)) {
            throw new SecurityException("Signature invalide (Authentification de l'émetteur échouée)");
        }

        // 4. Vérification des en-têtes de sécurité et extraction du message
        return context.verifySecurityHeaders(securedMessage);
    }
}