import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class Serveur {
    public static final int PORT = 5000;

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("  Serveur Multi-Clients sécurisé en attente sur le port " + PORT + "...");
            System.out.println("  Le serveur gère la communication dans des threads séparés.");

            while (true) {
                try {
                    // Attend et accepte une nouvelle connexion
                    Socket clientSocket = serverSocket.accept();

                    // Crée un gestionnaire pour ce client spécifique
                    ClientHandler handler = new ClientHandler(clientSocket);

                    // Lance un nouveau Thread pour gérer le client
                    Thread clientThread = new Thread(handler);
                    clientThread.start();

                    System.out.println(" Nouveau client accepté. Thread ID: " + clientThread.getId());

                } catch (IOException e) {
                    System.out.println(" Erreur lors de l'acceptation de la connexion: " + e.getMessage());
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}