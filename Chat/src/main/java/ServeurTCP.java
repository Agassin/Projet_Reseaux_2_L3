import java.io.*;
import java.net.*;

public class ServeurTCP {
    public static void main(String[] args) {
        try {
            ServerSocket serverSocket = new ServerSocket(5000);
            System.out.println("Serveur en attente de connexion...");

            Socket clientSocket = serverSocket.accept();
            System.out.println("Client connecté !");

            BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);

            String message;
            while ((message = in.readLine()) != null) {
                System.out.println("Client > " + message);

                if (message.equalsIgnoreCase("bye")) {
                    out.println("Connexion fermée. Au revoir !");
                    break;
                }

                out.println("Serveur a reçu: " + message);
            }

            System.out.println("Déconnexion du client...");
            in.close();
            out.close();
            clientSocket.close();
            serverSocket.close();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
