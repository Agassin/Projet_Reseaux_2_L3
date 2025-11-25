import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class Serveur {
    public static final int PORT = 5000;

    // Set synchronisé pour stocker toutes les instances de ClientHandler connectées
    private static final Set<ClientHandler> clients = Collections.synchronizedSet(new HashSet<>());

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("  Serveur Multi-Clients sécurisé en attente sur le port " + PORT + "...");
            System.out.println("  Fonctionnalité de chat multi-utilisateur activée.");

            while (true) {
                try {
                    // Attend et accepte une nouvelle connexion
                    Socket clientSocket = serverSocket.accept();
                    ClientHandler handler = new ClientHandler(clientSocket);

                    // L'ajout est géré dans le Handler après le succès du handshake

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

    /**
     * Ajoute un ClientHandler à la liste après un handshake réussi.
     */
    public static void addClient(ClientHandler client) {
        clients.add(client);
        System.out.println(" Clients actifs: " + clients.size());
    }

    /**
     * Diffuse un message clair à tous les clients, sauf l'expéditeur.
     * Chaque clientHandler se charge de signer et chiffrer avant l'envoi.
     */
    public static void broadcast(String message, ClientHandler sender) {
        System.out.println("\n [BROADCAST] Diffusé: " + message);
        for (ClientHandler client : clients) {
            // N'envoie pas le message à l'expéditeur
            if (client != sender) {
                client.sendMessage(message);
            }
        }
    }

    /**
     * Retire un client déconnecté du Set global.
     */
    public static void removeClient(ClientHandler client, String clientName) {
        if (clients.remove(client)) {
            System.out.println(" " + clientName + " a été déconnecté. Clients actifs restants: " + clients.size());
            // Diffuser un message d'information sur la déconnexion
            broadcast(clientName + " a quitté le chat.", client);
        }
    }
}