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

    @FXML public ListView<String> messageArea;
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

        // Initialiser la liste des salons
        roomList.getItems().add("Général");
        roomList.getSelectionModel().selectFirst();
        roomList.setOnMouseClicked(this::handleRoomSelection);
    }

    private void handleRoomSelection(MouseEvent event) {
        String selectedRoom = roomList.getSelectionModel().getSelectedItem();
        if (selectedRoom != null && !selectedRoom.equals(currentRoom)) {
            try {
                // (Ici, vous enverriez client.joinRoom(selectedRoom) au serveur)

                currentRoom = selectedRoom;
                currentRoomLabel.setText("Salon Actuel : " + currentRoom);
                messageArea.getItems().clear();
                displayMessage("--- Vous avez rejoint le salon: " + currentRoom + " ---");

            } catch (Exception e) {
                displayMessage("Erreur de changement de salon: " + e.getMessage());
            }
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
            try {
                // (Ici, vous enverriez client.requestPrivateRoom(privateUser) au serveur)

                Platform.runLater(() -> {
                    if (!roomList.getItems().contains(newRoomName)) {
                        roomList.getItems().add(newRoomName);
                    }
                    roomList.getSelectionModel().select(newRoomName);
                    handleRoomSelection(null);
                });

            } catch (Exception e) {
                displayMessage("Erreur lors de la création du salon: " + e.getMessage());
            }
        });
    }

    @FXML
    private void sendMessage() {
        String message = inputField.getText();
        if (message.isEmpty() || client == null) return;

        try {
            // CORRECTION : Le message brut, sendSecuredMessage ajoutera le username
            client.sendSecuredMessage(message);

            // Affichage local immédiat avec votre username
            displayMessage(username + " (" + currentRoom + "): " + message);
            inputField.clear();

        } catch (Exception e) {
            displayMessage("Erreur d'envoi du message: " + e.getMessage());
        }
    }

    public void displayMessage(String message) {
        Platform.runLater(() -> {
            messageArea.getItems().add(message);
            messageArea.scrollTo(messageArea.getItems().size() - 1);
        });
    }
}