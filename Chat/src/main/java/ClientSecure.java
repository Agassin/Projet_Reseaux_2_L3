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

    public static void main(String[] args) {
        try (Socket socket = new Socket(SERVER_HOST, SERVER_PORT)) {
            System.out.println("Connecté au serveur " + SERVER_HOST + ":" + SERVER_PORT);

            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            Scanner sc = new Scanner(System.in);

            String cle64Bit = in.readLine();
            if (cle64Bit == null) {
                throw new IOException("Impossible de recevoir la clé publique.");
            }
            byte[] CleEnBit = Base64.getDecoder().decode(cle64Bit);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec pubclient = new X509EncodedKeySpec(CleEnBit);
            PublicKey serveurPubCle = kf.generatePublic(pubclient);
            System.out.println("Clé publique RSA reçue du serveur.");

            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(128);
            SecretKey aesCle = kg.generateKey();
            byte[] aescleBytes = aesCle.getEncoded();

            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.ENCRYPT_MODE, serveurPubCle);
            byte[] encrypteAescle = rsaCipher.doFinal(aescleBytes);
            String encrypteAescleB64 = Base64.getEncoder().encodeToString(encrypteAescle);

            out.println(encrypteAescleB64);
            System.out.println("Clé AES générée et envoyée (chiffrée avec RSA).");

            String serverConfirm = in.readLine();
            if (serverConfirm != null) {
                System.out.println("Serveur > " + serverConfirm);
            }
            while (true) {
                System.out.print("Vous > ");
                String msg = sc.nextLine();

                String envoyer = encryptAndEncode(msg, new SecretKeySpec(aescleBytes, "AES"));
                out.println(envoyer);
                String[] parts = envoyer.split(":", 2);
                //System.out.println("Envoyé (chiffré): " + parts[1]);
                System.out.println("Envoyé (clair)  : " + msg);

                String serverLine = in.readLine();
                if (serverLine == null) break;

                String[] tok = serverLine.split(":", 2);
                if (tok.length != 2) {
                    System.out.println("Réponse serveur: format invalide");
                    continue;
                }
                byte[] iv = Base64.getDecoder().decode(tok[0]);
                byte[] cipherBytes = Base64.getDecoder().decode(tok[1]);

                //System.out.println("Reçu (chiffré)  : " + tok[1]);

                Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                aesCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aescleBytes, "AES"), new IvParameterSpec(iv));
                byte[] plainBytes = aesCipher.doFinal(cipherBytes);
                String plainText = new String(plainBytes, "UTF-8");
                System.out.println("Reçu (clair)    : " + plainText);

                if (msg.equalsIgnoreCase("bye")) {
                    System.out.println("Déconnexion demandée. Fin.");
                    break;
                }
            }

            in.close();
            out.close();
            sc.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String encryptAndEncode(String plain, SecretKeySpec aesCle) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecureRandom rnd = new SecureRandom();
        byte[] iv = new byte[16];
        rnd.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, aesCle, ivSpec);
        byte[] ct = cipher.doFinal(plain.getBytes("UTF-8"));
        String ivB64 = Base64.getEncoder().encodeToString(iv);
        String ctB64 = Base64.getEncoder().encodeToString(ct);
        return ivB64 + ":" + ctB64;
    }
}
