import java.io.*;
import java.net.Socket;
import java.security.*;
import javax.crypto.spec.*;

public class ServerReader implements Runnable {
    private Socket socket;
    private BufferedReader in;
    private PublicKey serverPublicKey;
    private SecretKeySpec aesKeySpec;
    private SecurityContext securityContext;
    private String username; // AJOUT

    // CONSTRUCTEUR MIS À JOUR pour accepter le nom d'utilisateur
    public ServerReader(Socket socket, BufferedReader in, PublicKey serverPublicKey, SecretKeySpec aesKeySpec, SecurityContext context, String username) {
        this.socket = socket;
        this.in = in;
        this.serverPublicKey = serverPublicKey;
        this.aesKeySpec = aesKeySpec;
        this.securityContext = context;
        this.username = username; // ASSIGNATION
    }

    @Override
    public void run() {
        String serverResponse;
        try {
            while ((serverResponse = in.readLine()) != null) {
                // Vérification et décryptage de la réponse du serveur (incluant les messages broadcastés)
                String decryptedResponse = CryptoUtils.verifyAndDecrypt(serverResponse, serverPublicKey, aesKeySpec, securityContext);

                // CORRECTION: Utilise '\r' pour revenir au début de la ligne et '\n' pour sauter de ligne
                // Cela efface la saisie partielle et réaffiche le message, puis l'invite.
                System.out.print("\r [CHAT] " + decryptedResponse + "\n " + username + " > ");
            }
        } catch (Exception e) {
            // Se produit souvent quand le socket est fermé par l'autre thread (normal)
            if (!socket.isClosed() && !(e instanceof InterruptedException)) {
                System.out.println("\n [Écoute] Connexion perdue ou erreur: " + e.getMessage());
            }
        }
    }
}