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

        // 1. Charger la page de connexion
        showLoginView();

        stage.show();
    }

    public void showLoginView() throws IOException {
        FXMLLoader fxmlLoader = new FXMLLoader(ChatAppFx.class.getResource("LoginView.fxml"));
        Scene scene = new Scene(fxmlLoader.load(), 350, 250);

        LoginController loginController = fxmlLoader.getController();
        loginController.setApp(this);

        primaryStage.setTitle("Connexion Chat Sécurisé FX");
        primaryStage.setScene(scene);
        primaryStage.centerOnScreen();
    }

    public void showErrorAlert(String details) {
        Alert alert = new Alert(AlertType.ERROR);
        alert.setTitle("Erreur de Connexion");
        alert.setHeaderText("Impossible de se connecter au serveur.");
        alert.setContentText("Détails: " + details);
        alert.showAndWait();
    }

    // Lance l'interface du chat après une authentification réussie.
    public void startChat(String username, ClientSecureFX client) throws Exception {
        FXMLLoader fxmlLoader = new FXMLLoader(ChatAppFx.class.getResource("ChatView.fxml"));
        Scene scene = new Scene(fxmlLoader.load(), 800, 500);

        ClientController controller = fxmlLoader.getController();

        // 1. Lier le client et le username au contrôleur
        controller.setClient(client);
        controller.setUsername(username);

        // 2. Démarrer le thread d'écoute AVANT d'afficher la fenêtre
        client.startListening(controller);

        // 3. Afficher la fenêtre de chat (réutilisation de la Stage)
        primaryStage.setTitle("Chat Sécurisé FX - " + username);
        primaryStage.setScene(scene);
        primaryStage.centerOnScreen();

        // 4. Message de connexion initial (le serveur le diffusera)
        client.sendSecuredMessage("Général|Connexion.");
    }

    public static void main(String[] args) {
        launch(args);
    }
}