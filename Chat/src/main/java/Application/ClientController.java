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
        System.out.println("[CONTROLLER] Initialisation...");

        inputField.setOnAction(event -> sendMessage());

        roomList.getItems().add("Général");
        roomList.getSelectionModel().selectFirst();
        roomList.setOnMouseClicked(this::handleRoomSelection);
        currentRoomLabel.setText("Salon Actuel : " + currentRoom);

        System.out.println("[CONTROLLER] ✓ Interface initialisée");
    }

    private void handleRoomSelection(MouseEvent event) {
        String selectedRoom = roomList.getSelectionModel().getSelectedItem();
        if (selectedRoom != null && !selectedRoom.equals(currentRoom)) {
            currentRoom = selectedRoom;
            currentRoomLabel.setText("Salon Actuel : " + currentRoom);
            messageArea.getItems().clear();
            displayMessage("--- Vous avez rejoint: " + currentRoom + " ---");
        }
    }

    @FXML
    private void createPrivateRoom() {
        TextInputDialog dialog = new TextInputDialog();
        dialog.setTitle("Nouveau Salon Privé");
        dialog.setHeaderText("Nom de l'utilisateur :");
        dialog.setContentText("Utilisateur :");

        Optional<String> result = dialog.showAndWait();
        result.ifPresent(privateUser -> {
            String newRoomName = "Privé avec " + privateUser;
            Platform.runLater(() -> {
                if (!roomList.getItems().contains(newRoomName)) {
                    roomList.getItems().add(newRoomName);
                }
                roomList.getSelectionModel().select(newRoomName);
                handleRoomSelection(null);
            });
        });
    }

    @FXML
    private void sendMessage() {
        String message = inputField.getText().trim();
        if (message.isEmpty() || client == null) return;

        try {
            // Format: SALON|MESSAGE
            String messageToSend = currentRoom + "|" + message;
            client.sendSecuredMessage(messageToSend);

            // ⭐ NE PAS afficher localement (le serveur va le broadcaster)
            // On le verra quand le serveur nous le renverra

            inputField.clear();

        } catch (Exception e) {
            displayMessage("[ERREUR ENVOI] " + e.getMessage());
            e.printStackTrace();
        }
    }

    public void displayMessage(String message) {
        Platform.runLater(() -> {
            messageArea.getItems().add(message);
            messageArea.scrollTo(messageArea.getItems().size() - 1);
        });
    }
}