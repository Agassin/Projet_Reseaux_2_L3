package Application;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.stage.Stage;

import java.io.IOException;

public class ChatAppFx extends Application {

    @Override
    public void start(Stage stage) throws IOException {

        // 1. Charger le FXML et obtenir le contrôleur
        FXMLLoader fxmlLoader = new FXMLLoader(ChatAppFx.class.getResource("ChatView.fxml"));
        Scene scene = new Scene(fxmlLoader.load(), 600, 400);

        ClientController controller = fxmlLoader.getController();

        try {

            ClientSecureFX client = new ClientSecureFX(ClientSecureFX.SERVER_HOST, ClientSecureFX.SERVER_PORT);

            // 3. Lier l'instance client au contrôleur
            controller.setClient(client);

            // 4. Démarrer le thread d'écoute des messages du serveur
            client.startListening(controller);

            // 5. Afficher la fenêtre si le handshake a réussi
            stage.setTitle("Chat Sécurisé FX");
            stage.setScene(scene);
            stage.show();

        } catch (Exception e) {
            // Gérer les erreurs de connexion ou de sécurité
            System.err.println("ERREUR: Impossible de démarrer le client réseau.");
            System.err.println("Vérifiez que le Serveur est lancé et que les configurations de sécurité sont correctes.");
            System.err.println("Détail: " + e.getMessage());

            stage.setTitle("Erreur de Connexion");

        }
    }

    public static void main(String[] args) {
        launch(args);
    }
}