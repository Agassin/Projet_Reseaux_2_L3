import java.io.IOException;
import java.net.*;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

// Importation des classes de sécurité mises à jour
import Security.CryptoUtils;
import Security.SecurityContext;

public class Serveur {
    public static final int PORT = 5000;

    // Set synchronisé pour stocker toutes les instances de ClientHandler connectées
    private static final Set<ClientHandler> clients = Collections.synchronizedSet(new HashSet<>());

    public static void main(String[] args) {
        // ⭐ MISE À JOUR POUR PERMETTRE LA RÉUTILISATION DU PORT (SO_REUSEADDR)
        try (ServerSocket serverSocket = new ServerSocket()) {
            serverSocket.setReuseAddress(true);
            serverSocket.bind(new InetSocketAddress(PORT));

            System.out.println("  Serveur Multi-Clients sécurisé en attente sur le port " + PORT + "...");
            System.out.println("  Fonctionnalité de chat multi-utilisateur activée.");

            while (true) {
                try {
                    // Attend et accepte une nouvelle connexion
                    Socket clientSocket = serverSocket.accept();
                    ClientHandler handler = new ClientHandler(clientSocket);

                    // L'ajout est géré dans le Handler après le succès du handshake
                    // et l'authentification

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
     * Ajoute un ClientHandler à la liste et diffuse la liste des utilisateurs.
     */
    public static void addClient(ClientHandler client) {
        clients.add(client);
        System.out.println(" Clients actifs: " + clients.size());
        broadcastUserList(); // Met à jour la liste des utilisateurs chez tous les clients
    }

    /**
     * Diffuse un message clair à tous les clients, sauf l'expéditeur.
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
     * Transmet un message privé (chiffré) à un destinataire spécifique.
     */
    public static void privateMessage(String recipientName, String senderName, String message) {
        System.out.println("\n [PRIVATE] De " + senderName + " à " + recipientName + ": " + message);

        ClientHandler recipientHandler = clients.stream()
                .filter(c -> recipientName.equalsIgnoreCase(c.getClientName()))
                .findFirst()
                .orElse(null);

        if (recipientHandler != null) {
            // Le message commence par PM: pour que le client sache comment le traiter
            String pmCommand = "PM:" + senderName + ":" + message;
            recipientHandler.sendMessage(pmCommand);
            System.out.println(" [PRIVATE] Message envoyé avec succès à " + recipientName);
        } else {
            // Optionnel: informer l'expéditeur que le destinataire n'est pas en ligne.
            // Pour l'instant, on se contente de l'afficher côté serveur.
            System.out.println(" [PRIVATE] Destinataire " + recipientName + " non trouvé.");
        }
    }

    /**
     * Diffuse la liste des utilisateurs actifs.
     */
    public static void broadcastUserList() {
        // Collecte tous les noms de clients authentifiés
        String userListString = clients.stream()
                .filter(ClientHandler::isAuthenticated) // S'assurer qu'il est authentifié
                .map(ClientHandler::getClientName)
                .collect(Collectors.joining(","));

        String command = "USERLIST:" + userListString;

        // Envoie la commande USERLIST à TOUS les clients authentifiés
        for (ClientHandler client : clients) {
            if (client.isAuthenticated()) {
                client.sendMessage(command);
            }
        }
        System.out.println(" [USERLIST] Diffusée: " + userListString);
    }

    /**
     * Retire un client déconnecté du Set global.
     */
    public static void removeClient(ClientHandler client, String clientName) {
        if (clients.remove(client)) {
            System.out.println(" " + clientName + " a été déconnecté. Clients actifs restants: " + clients.size());
            broadcast(clientName + " a quitté le chat.", null);
            broadcastUserList(); // Met à jour la liste des utilisateurs
        }
    }
}