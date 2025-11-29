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
    public void setPrimaryStage(Stage primaryStage) {
        this.primaryStage = primaryStage;
        this.mainApp = (ChatAppFx) primaryStage.getScene().getWindow().getScene().getWindow().getScene().getWindow().getScene().getUserData(); // Méthode pour récupérer l'instance de ChatAppFx (simplifiable avec d'autres patterns)
        // Pour l'instant, faisons simple : on suppose que ChatAppFx a une méthode statique pour obtenir l'instance si nécessaire, ou on modifie le flow de start() dans ChatAppFx pour passer l'instance.
    }

    @FXML
    private void handleLogin() {
        String username = usernameField.getText().trim();
        String password = passwordField.getText();

        if (username.isEmpty()) {
            return;
        }

        try {
            // Connexion et Handshake
            ClientSecureFX client = new ClientSecureFX(ClientSecureFX.SERVER_HOST, ClientSecureFX.SERVER_PORT, username);
            client.sendLoginCredentials(username, password);

            // Succès : Passer au chat en utilisant l'instance mainApp injectée
            mainApp.startChat(username, client);

            // Fermer la fenêtre de connexion
            ((Stage) loginButton.getScene().getWindow()).close();

        } catch (Exception e) {
            System.err.println("ERREUR: Échec de la connexion ou de l'authentification.");
            System.err.println("Détail: " + e.getMessage());
            // Afficher une alerte via l'instance mainApp
            mainApp.showErrorAlert("Erreur de connexion : " + e.getMessage());
            if (primaryStage != null) {
                primaryStage.close();
            }
        }
    }

    public void setApp(ChatAppFx mainApp, Stage primaryStage) {
        this.mainApp = mainApp;
        this.primaryStage = primaryStage;
    }
}