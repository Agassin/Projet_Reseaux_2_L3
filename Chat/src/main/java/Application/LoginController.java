package Application;

import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.stage.Stage;

import java.io.IOException;

public class LoginController {

    @FXML private TextField usernameField;
    @FXML private PasswordField passwordField;
    @FXML private Button loginButton;

    private Stage primaryStage;
    private ChatAppFx mainApp;

    // Méthode simple pour injecter l'application principale (le Stage)
    public void setApp(ChatAppFx mainApp, Stage primaryStage) {
        this.mainApp = mainApp;
        this.primaryStage = primaryStage;
    }

    // Ancien setPrimaryStage avec la logique getWindow().getScene() est retiré.

    @FXML
    private void handleLogin() {
        String username = usernameField.getText().trim();
        String password = passwordField.getText();

        if (username.isEmpty()) {
            return;
        }

        try {
            // 1. Tenter de se connecter et effectuer le Handshake
            ClientSecureFX client = new ClientSecureFX(ClientSecureFX.SERVER_HOST, ClientSecureFX.SERVER_PORT, username);

            // 2. Authentification BLOQUANTE : attend la réponse AUTH_OK du serveur.
            client.sendLoginCredentials(username, password);

            // 3. Succès : Lancer le chat (qui va démarrer l'écoute et envoyer le message "Connexion.")
            mainApp.startChat(username, client);

            // 4. Fermer la fenêtre de connexion
            ((Stage) loginButton.getScene().getWindow()).close();

        } catch (Exception e) {
            System.err.println("ERREUR: Échec de la connexion ou de l'authentification.");
            System.err.println("Détail: " + e.getMessage());

            // Afficher l'alerte. showErrorAlert est configurée pour fermer l'application après.
            mainApp.showErrorAlert("Échec du login. " + e.getMessage());
        }
    }
}