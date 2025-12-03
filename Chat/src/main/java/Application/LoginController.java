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
        System.out.println("[DEBUG] LoginController initialisé");
    }

    @FXML
    private void handleLogin() {
        System.out.println("\n========== DÉBUT CONNEXION ==========");

        String username = usernameField.getText().trim();
        String password = passwordField.getText();

        System.out.println("[1] Username: " + username);
        System.out.println("[2] Password: " + (password.isEmpty() ? "vide" : "***"));

        if (username.isEmpty()) {
            System.out.println("[ERREUR] Username vide");
            return;
        }

        ClientSecureFX client = null;

        try {
            // 1. Tenter de se connecter et effectuer le Handshake
            System.out.println("[3] Tentative de connexion à " + ClientSecureFX.SERVER_HOST + ":" + ClientSecureFX.SERVER_PORT);
            client = new ClientSecureFX(ClientSecureFX.SERVER_HOST, ClientSecureFX.SERVER_PORT, username);
            System.out.println("[4] ✓ Connexion établie - Handshake réussi");

            // 2. Authentification BLOQUANTE : attend la réponse AUTH_OK du serveur.
            System.out.println("[5] Envoi des credentials...");
            client.sendLoginCredentials(username, password);
            System.out.println("[6] ✓ Authentification réussie (AUTH_OK reçu)");

            // 3. Succès : Lancer le chat
            System.out.println("[7] Lancement de l'interface chat...");
            mainApp.startChat(username, client);
            System.out.println("[8] ✓ Interface chat lancée");

            // 4. Fermer la fenêtre de connexion
            System.out.println("[9] Fermeture de la fenêtre de login...");
            System.out.println("[10] ✓ Login terminé avec succès");
            System.out.println("========== CONNEXION RÉUSSIE ==========\n");

        } catch (java.net.ConnectException e) {
            System.err.println("\n[ERREUR RÉSEAU] Impossible de se connecter au serveur");
            System.err.println("Cause: Le serveur n'est pas démarré ou n'écoute pas sur " + ClientSecureFX.SERVER_HOST + ":" + ClientSecureFX.SERVER_PORT);
            mainApp.showErrorAlert("Serveur inaccessible. Vérifiez qu'il est bien démarré.");

        } catch (java.net.SocketTimeoutException e) {
            System.err.println("\n[ERREUR TIMEOUT] Le serveur ne répond pas");
            mainApp.showErrorAlert("Le serveur met trop de temps à répondre.");

        } catch (SecurityException e) {
            System.err.println("\n[ERREUR SÉCURITÉ] " + e.getMessage());
            e.printStackTrace();
            mainApp.showErrorAlert("Erreur de sécurité: " + e.getMessage());
            if (client != null) {
                client.closeConnection();
            }

        } catch (Exception e) {
            System.err.println("\n[ERREUR INATTENDUE] Type: " + e.getClass().getName());
            System.err.println("Message: " + e.getMessage());
            System.err.println("Stack trace:");
            e.printStackTrace();

            mainApp.showErrorAlert("Erreur: " + e.getMessage());
            if (client != null) {
                client.closeConnection();
            }
        }
    }
}