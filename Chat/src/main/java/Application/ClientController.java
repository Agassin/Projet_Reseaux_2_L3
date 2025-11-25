package Application;

import javafx.fxml.FXML;
import javafx.scene.control.ListView;
import javafx.scene.control.TextField;
import javafx.application.Platform;

public class ClientController {

    @FXML
    public ListView<String> messageArea;

    @FXML
    private TextField inputField;

    private ClientSecureFX client;

    public void setClient(ClientSecureFX client) {
        this.client = client;
    }

    @FXML
    private void sendMessage() {
        String message = inputField.getText();
        if (message.isEmpty() || client == null) return;

        try {
            // Envoyer le message (il sera préfixé par le nom d'utilisateur dans ClientSecureFX)
            client.sendSecuredMessage(message);

            // Affichage local immédiat
            displayMessage("Vous: " + message);
            inputField.clear();

        } catch (Exception e) {
            displayMessage("Erreur d'envoi du message: " + e.getMessage());
        }
    }

    // MÉTHODE CRUCIALE pour mettre à jour la GUI depuis le thread réseau
    public void displayMessage(String message) {
        // Utiliser Platform.runLater pour s'assurer que la modification de l'interface
        // est exécutée sur le thread principal de JavaFX.
        Platform.runLater(() -> {
            messageArea.getItems().add(message);
            // Faire défiler vers le bas pour voir le nouveau message
            messageArea.scrollTo(messageArea.getItems().size() - 1);
        });
    }

    @FXML
    public void initialize() {
        // Permettre l'envoi du message en appuyant sur ENTER
        inputField.setOnAction(event -> sendMessage());
        // Vous pouvez initialiser d'autres choses ici si nécessaire
    }
}