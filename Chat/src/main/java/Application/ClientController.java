package Application;

import javafx.fxml.FXML;
import javafx.scene.control.ListView;
import javafx.scene.control.TextField;
import javafx.scene.control.Label;
import javafx.application.Platform;
import javafx.scene.input.MouseEvent;
import javafx.scene.control.TextInputDialog;
import java.util.Optional;


public class ClientController {

    @FXML private ListView<String> messageArea;
    @FXML private TextField inputField;
    @FXML private ListView<String> roomList;
    @FXML private Label currentRoomLabel;

    private ClientSecureFX client;
    private String username;
    private String currentRoom = "Général";

    public void setClient(ClientSecureFX client) {
        this.client = client;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    @FXML
    public void initialize() {
        inputField.setOnAction(event -> sendMessage());

        roomList.getItems().add("Général");
        roomList.getSelectionModel().selectFirst();
        roomList.setOnMouseClicked(this::handleRoomSelection);
        currentRoomLabel.setText("Salon Actuel : " + currentRoom);
    }

    private void handleRoomSelection(MouseEvent event) {
        String selectedRoom = roomList.getSelectionModel().getSelectedItem();
        if (selectedRoom != null && !selectedRoom.equals(currentRoom)) {
            // Logique de changement de salon (à implémenter côté serveur)
            currentRoom = selectedRoom;
            currentRoomLabel.setText("Salon Actuel : " + currentRoom);
            messageArea.getItems().clear();
            displayMessage("--- Vous avez rejoint le salon: " + currentRoom + " ---");
            // Envoyer un message au serveur pour rejoindre le salon si nécessaire
        }
    }

    @FXML
    private void createPrivateRoom() {
        TextInputDialog dialog = new TextInputDialog();
        dialog.setTitle("Nouveau Salon Privé");
        dialog.setHeaderText("Entrez le nom de l'utilisateur avec qui chatter :");
        dialog.setContentText("Nom de l'utilisateur :");

        Optional<String> result = dialog.showAndWait();
        result.ifPresent(privateUser -> {
            String newRoomName = "Privé avec " + privateUser;
            Platform.runLater(() -> {
                if (!roomList.getItems().contains(newRoomName)) {
                    roomList.getItems().add(newRoomName);
                }
                roomList.getSelectionModel().select(newRoomName);
                handleRoomSelection(null); // Force le changement d'affichage
            });
        });
    }

    @FXML
    private void sendMessage() {
        String message = inputField.getText();
        if (message.isEmpty() || client == null) return;

        try {
            // Format du message envoyé au serveur : SALON|MESSAGE
            String messageToSend = currentRoom + "|" + message;
            client.sendSecuredMessage(messageToSend);

            // Affichage local immédiat
            displayMessage(username + " (" + currentRoom + "): " + message);
            inputField.clear();

        } catch (Exception e) {
            displayMessage("[ERREUR ENVOI] " + e.getMessage());
        }
    }

    public void displayMessage(String message) {
        // Le serveur nous envoie : [NOM_EXPEDITEUR] : [SALON] | [MESSAGE]
        // Nous allons l'afficher tel quel pour le moment.
        Platform.runLater(() -> {
            messageArea.getItems().add(message);
            messageArea.scrollTo(messageArea.getItems().size() - 1);
        });
    }
}