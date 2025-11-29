package Application;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.stage.Stage;
import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;
import java.io.IOException;

public class ChatAppFx extends Application {

    private Stage primaryStage;

    @Override
    public void start(Stage stage) throws IOException {
        this.primaryStage = stage;

        // 1. Charger le FXML de la page de connexion
        FXMLLoader fxmlLoader = new FXMLLoader(ChatAppFx.class.getResource("LoginView.fxml"));
        Scene scene = new Scene(fxmlLoader.load(), 350, 250);

        LoginController loginController = fxmlLoader.getController();

        stage.setTitle("Connexion Chat Sécurisé FX");
        stage.setScene(scene);

        // 2. Injecter l'instance 'this'
        loginController.setApp(this, stage);

        stage.show();
    }


    public void showErrorAlert(String details) {
        Alert alert = new Alert(AlertType.ERROR);
        alert.setTitle("Erreur de Connexion");
        alert.setHeaderText("Impossible de se connecter au serveur.");
        alert.setContentText("Vérifiez que le Serveur est lancé et les configurations. Détails: " + details);
        alert.showAndWait();

        // Utilisation sécurisée de primaryStage pour fermer l'application après l'erreur
        if (primaryStage != null) {
            javafx.application.Platform.runLater(primaryStage::close);
        }
    }

    // Lance l'interface du chat après une authentification réussie.
    public void startChat(String username, ClientSecureFX client) throws Exception {
        FXMLLoader fxmlLoader = new FXMLLoader(ChatAppFx.class.getResource("ChatView.fxml"));
        Scene scene = new Scene(fxmlLoader.load(), 800, 500);

        ClientController controller = fxmlLoader.getController();

        // 1. Lier l'instance client au contrôleur
        controller.setClient(client);

        // 2. Démarrer le thread d'écoute des messages du serveur (PRÊT À RECEVOIR)
        client.startListening(controller);

        // 3. ENVOYER le message de connexion APRES que l'écoute est lancée
        client.sendSecuredMessage(username + ": Connexion.");

        // 4. Afficher la fenêtre de chat
        primaryStage.setTitle("Chat Sécurisé FX - Utilisateur: " + username);
        primaryStage.setScene(scene);
        primaryStage.show();
        primaryStage.centerOnScreen();
    }

    public static void main(String[] args) {
        launch(args);
    }
}