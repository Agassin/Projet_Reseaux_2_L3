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

    // Référence à la nouvelle classe réseau
    private ClientSecureFX client; // <--- CORRIGÉ

    public void setClient(ClientSecureFX client) { // <--- CORRIGÉ
        this.client = client;
    }

    @FXML
    private void sendMessage() {
        String message = inputField.getText();
        if (message.isEmpty() || client == null) return;

        try {
            client.sendSecuredMessage(message);

            displayMessage("Vous: " + message);
            inputField.clear();

            if (message.equalsIgnoreCase("bye")) {
                displayMessage("Déconnexion demandée...");
            }

        } catch (Exception e) {
            displayMessage("Erreur d'envoi du message: " + e.getMessage());
        }
    }

    public void displayMessage(String message) {
        // ESSENTIEL : Utiliser Platform.runLater
        Platform.runLater(() -> {
            messageArea.getItems().add(message);
        });
    }

    @FXML
    public void initialize() {
        // Permet d'envoyer en appuyant sur ENTER
        inputField.setOnAction(event -> sendMessage());
    }
}