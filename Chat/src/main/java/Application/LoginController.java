package Application;

import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;

public class LoginController {

    @FXML private TextField usernameField;
    @FXML private PasswordField passwordField;
    @FXML private Button loginButton;

    private ChatAppFx mainApp;

    public void setApp(ChatAppFx mainApp) {
        this.mainApp = mainApp;
    }

    @FXML
    private void handleLogin() {
        String username = usernameField.getText().trim();
        String password = passwordField.getText();

        if (username.isEmpty()) return;

        ClientSecureFX client = null;

        try {
            // 1. Handshake
            client = new ClientSecureFX(ClientSecureFX.SERVER_HOST, ClientSecureFX.SERVER_PORT, username);

            // 2. Authentification BLOQUANTE
            client.sendLoginCredentials(username, password);

            // 3. Succès : Lancer le chat (qui va changer la Scene)
            mainApp.startChat(username, client);

            // ⚠️ PAS DE CLOSE() ICI, CAR ON RÉUTILISE LA PRIMARYSTAGE

        } catch (java.net.ConnectException e) {
            mainApp.showErrorAlert("Serveur inaccessible. Vérifiez qu'il est démarré.");
        } catch (SecurityException e) {
            mainApp.showErrorAlert("Erreur de sécurité ou login refusé: " + e.getMessage());
            if (client != null) client.closeConnection();
        } catch (Exception e) {
            mainApp.showErrorAlert("Erreur inattendue: " + e.getMessage());
            if (client != null) client.closeConnection();
        }
    }
}