import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Base64;
import java.util.StringTokenizer;

public class ServeurSecure {
    public static final int PORT = 5000;

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("Serveur sécurisé en attente de connexion sur le port " + PORT + "...");
            try (Socket clientSocket = serverSocket.accept()) {
                System.out.println("Client connecté : " + clientSocket.getRemoteSocketAddress());

                BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);

                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(2048);
                KeyPair kp = kpg.generateKeyPair();
                PrivateKey privateCle = kp.getPrivate();
                PublicKey publicCle = kp.getPublic();

                String pubKeyB64 = Base64.getEncoder().encodeToString(publicCle.getEncoded());
                out.println(pubKeyB64);
                System.out.println("Clé publique RSA envoyée au client.");

                String encrypteAesCleB64 = in.readLine();
                if (encrypteAesCleB64 == null) {
                    throw new IOException("Échange de clé interrompu.");
                }
                byte[] encrypteAesCle = Base64.getDecoder().decode(encrypteAesCleB64);

                Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                rsaCipher.init(Cipher.DECRYPT_MODE, privateCle);
                byte[] aesCleBytes = rsaCipher.doFinal(encrypteAesCle);
                SecretKeySpec aesCle = new SecretKeySpec(aesCleBytes, "AES");
                System.out.println("Clé AES reçue et déchiffrée (128 bits).");

                out.println("AES-OK");

                String line;
                while ((line = in.readLine()) != null) {
                    StringTokenizer st = new StringTokenizer(line, ":");
                    if (st.countTokens() != 2) {
                        System.out.println("Format invalide reçu : " + line);
                        continue;
                    }
                    String ivB64 = st.nextToken();
                    String cipherB64 = st.nextToken();

                    byte[] iv = Base64.getDecoder().decode(ivB64);
                    byte[] cipherBytes = Base64.getDecoder().decode(cipherB64);

                    System.out.println("Reçu (chiffré) : " + cipherB64);

                    Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    aesCipher.init(Cipher.DECRYPT_MODE, aesCle, new IvParameterSpec(iv));
                    byte[] plainBytes = aesCipher.doFinal(cipherBytes);
                    String plainText = new String(plainBytes, "UTF-8");

                    System.out.println("Reçu (clair)   : " + plainText);

                    if (plainText.equalsIgnoreCase("bye")) {
                        String reply = "Au revoir";
                        String rep = encryptAndEncode(reply, aesCle);
                        out.println(rep);
                        System.out.println("Connexion fermée par demande 'bye'.");
                        break;
                    } else {
                        String reply = "Serveur a reçu: " + plainText;
                        String rep = encryptAndEncode(reply, aesCle);
                        out.println(rep);
                        String[] parts = rep.split(":", 2);
                        System.out.println("Envoyé (chiffré): " + parts[1]);
                        System.out.println("Envoyé (clair)  : " + reply);
                    }
                }

                System.out.println("Fermeture des flux et socket côté serveur.");
                in.close();
                out.close();
            }
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
