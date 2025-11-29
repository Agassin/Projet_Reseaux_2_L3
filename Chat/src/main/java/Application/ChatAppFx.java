package Application;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.stage.Stage;
import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;
import java.io.IOException;

public class ChatAppFx extends Application {

    private Stage primaryStage; // Garder une référence au Stage principal

    // Dans ChatAppFx.java (méthode start)
    @Override
    public void start(Stage stage) throws IOException {
        this.primaryStage = stage;

        FXMLLoader fxmlLoader = new FXMLLoader(ChatAppFx.class.getResource("LoginView.fxml"));
        Scene scene = new Scene(fxmlLoader.load(), 350, 250);

        LoginController loginController = fxmlLoader.getController();

        stage.setTitle("Connexion Chat Sécurisé FX");
        stage.setScene(scene); // <-- Définir la Scene en premier.

        // Injecter l'instance 'this' (l'instance courante et valide de ChatAppFx)
        loginController.setApp(this, stage); // <-- Utiliser 'this'

        stage.show();
    }


    // Ancien getUsername() supprimé.
    // showErrorAlert est conservé, mais nous l'appelons maintenant depuis le LoginController
    public void showErrorAlert(String details) {
        Alert alert = new Alert(AlertType.ERROR);
        alert.setTitle("Erreur de Connexion");
        alert.setHeaderText("Impossible de se connecter au serveur.");
        alert.setContentText("Vérifiez que le Serveur est lancé. Détails: " + details);
        alert.showAndWait();
        javafx.application.Platform.runLater(stage::close);

    }

    // Nouvelle méthode pour passer du login au chat principal
    public void startChat(String username, ClientSecureFX client) throws IOException {
        // Charger le FXML de la vue du chat
        FXMLLoader fxmlLoader = new FXMLLoader(ChatAppFx.class.getResource("ChatView.fxml"));
        Scene scene = new Scene(fxmlLoader.load(), 800, 500); // Agrandir la fenêtre pour les salons

        ClientController controller = fxmlLoader.getController();

        // Lier l'instance client au contrôleur
        controller.setClient(client);

        // Démarrer le thread d'écoute des messages du serveur
        client.startListening(controller);

        // Afficher la fenêtre de chat
        primaryStage.setTitle("Chat Sécurisé FX - Utilisateur: " + username);
        primaryStage.setScene(scene);
        primaryStage.show();
        primaryStage.centerOnScreen();
    }

    public static void main(String[] args) {
        launch(args);
    }
}