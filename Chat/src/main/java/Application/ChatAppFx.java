package Application;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.stage.Stage;
import javafx.scene.control.TextInputDialog;
import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;
import java.io.IOException;
import java.util.Optional;

public class ChatAppFx extends Application {

    @Override
    public void start(Stage stage) throws IOException {

        // 1. Demander le nom d'utilisateur au démarrage
        String username = getUsername();
        if (username == null || username.trim().isEmpty()) {
            System.err.println("Nom d'utilisateur requis. Fermeture.");
            return;
        }

        // 2. Charger le FXML et obtenir le contrôleur
        FXMLLoader fxmlLoader = new FXMLLoader(ChatAppFx.class.getResource("ChatView.fxml"));
        Scene scene = new Scene(fxmlLoader.load(), 600, 400);

        ClientController controller = fxmlLoader.getController();

        try {
            // 3. Initialiser le client avec le nom d'utilisateur (Handshake)
            ClientSecureFX client = new ClientSecureFX(ClientSecureFX.SERVER_HOST, ClientSecureFX.SERVER_PORT, username);

            // 4. Lier l'instance client au contrôleur
            controller.setClient(client);

            // 5. Démarrer le thread d'écoute des messages du serveur
            client.startListening(controller);

            // 6. Afficher la fenêtre
            stage.setTitle("Chat Sécurisé FX - Utilisateur: " + username);
            stage.setScene(scene);
            stage.show();

        } catch (Exception e) {
            // Gérer les erreurs de connexion ou de sécurité (e.g., serveur non lancé)
            System.err.println("ERREUR: Impossible de démarrer le client réseau.");
            System.err.println("Détail: " + e.getMessage());
            showErrorAlert(stage, e.getMessage());
        }
    }

    // Ajout d'une méthode pour demander le nom d'utilisateur via une boîte de dialogue
    private String getUsername() {
        TextInputDialog dialog = new TextInputDialog("UtilisateurFX");
        dialog.setTitle("Nom d'utilisateur");
        dialog.setHeaderText("Entrez votre nom d'utilisateur pour le chat :");
        dialog.setContentText("Nom :");

        Optional<String> result = dialog.showAndWait();
        return result.orElse(null);
    }

    private void showErrorAlert(Stage stage, String details) {
        Alert alert = new Alert(AlertType.ERROR);
        alert.setTitle("Erreur de Connexion");
        alert.setHeaderText("Impossible de se connecter au serveur.");
        alert.setContentText("Vérifiez que le Serveur est lancé et que les configurations de sécurité sont correctes. Détails: " + details);
        alert.showAndWait();
        stage.close();
    }
    public static void main(String[] args) {
        launch(args);
    }
}