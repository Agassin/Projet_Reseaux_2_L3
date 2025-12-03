package appFX;

import java.io.BufferedReader;
import java.io.IOException;

// Importation des classes de sécurité mises à jour
import Security.CryptoUtils;

public class ClientReaderFX implements Runnable {
    private final ClientSecureFX client;
    private final BufferedReader in;

    public ClientReaderFX(ClientSecureFX client, BufferedReader in) {
        this.client = client;
        this.in = in;
    }

    @Override
    public void run() {
        String serverResponseEncrypted;

        try {
            while (!Thread.currentThread().isInterrupted() && (serverResponseEncrypted = in.readLine()) != null) {

                // Le décryptage peut lancer une Exception (GeneralSecurityException, SecurityException, etc.)
                String decryptedResponse = CryptoUtils.verifyAndDecrypt(
                        serverResponseEncrypted,
                        client.getServerPublicKey(),
                        client.getAesKeySpec(),
                        client.getSecurityContext());

                // ⭐ Début du traitement des commandes du protocole
                if (decryptedResponse.startsWith("USERLIST:")) {
                    String userList = decryptedResponse.substring("USERLIST:".length());
                    client.handleUserList(userList);

                } else if (decryptedResponse.startsWith("PM:")) {
                    String pmContent = decryptedResponse.substring("PM:".length());
                    String[] parts = pmContent.split(":", 2);
                    if (parts.length == 2) {
                        String sender = parts[0];
                        String message = parts[1];
                        client.handlePrivateMessage(sender, message);
                    }
                } else {
                    client.appendGeneralMessage(decryptedResponse);
                }
            }
        } catch (IOException e) {
            // Erreur de socket (connexion perdue)
            if (client.socket != null && !client.socket.isClosed()) {
                System.err.println("ClientReaderFX: Connexion perdue (IOException): " + e.getMessage());
                // Signalons à l'UI
                client.appendGeneralMessage("ERREUR Système: Connexion au serveur perdue.");
            }
        } catch (Exception e) {
            // ⭐ ATTENTION: Ce bloc capture l'EXCEPTION NON GÉRÉE de CryptoUtils.verifyAndDecrypt
            // et les erreurs de sécurité (SecurityException).
            if (!Thread.currentThread().isInterrupted()) {
                client.appendGeneralMessage("ERREUR Sécurité: Message rejeté - " + e.getMessage());
                System.err.println("ClientReaderFX: Erreur critique (Décryptage/Sécurité): " + e.getMessage());
            }
        } finally {
            // S'assurer que le socket est fermé
            try {
                if (client.socket != null && !client.socket.isClosed()) {
                    client.disconnect();
                }
            } catch (Exception ignore) { /* ignore */ }
        }
    }
}