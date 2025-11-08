import java.io.*;
import java.net.*;

public class ClientTCP {
    public static void main(String[] args) {
        try {
            Socket socket = new Socket("localhost", 5000);
            System.out.println("Connecté au serveur");

            BufferedReader userInput = new BufferedReader(new InputStreamReader(System.in));
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            String message;
            while (true) {
                System.out.print("Vous > ");
                message = userInput.readLine();
                out.println(message);

                if (message.equalsIgnoreCase("bye")) {
                    System.out.println("Fermeture de la connexion...");
                    break;
                }
                System.out.println("Serveur > " + in.readLine());
            }

            in.close();
            out.close();
            socket.close();
            System.out.println("Client terminé.");

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
