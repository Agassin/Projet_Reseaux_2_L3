package Application;

import javafx.fxml.FXML;
import javafx.scene.control.ListView;
import javafx.scene.control.TextField;
import javafx.scene.control.Label;
import javafx.application.Platform;
import javafx.scene.input.MouseEvent;

import java.util.Optional;
import javafx.scene.control.TextInputDialog;
import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;

public class ClientController {

    @FXML public ListView<String> messageArea;
    @FXML private TextField inputField;
    @FXML private ListView<String> roomList; // NOUVEAU
    @FXML private Label currentRoomLabel;   // NOUVEAU

    private ClientSecureFX client;
    private String currentRoom = "Général"; //

    // ... setClient est inchangé

    @FXML
    public void initialize() {
        // Permettre l'envoi du message en appuyant sur ENTER
        inputField.setOnAction(event -> sendMessage());

        // NOUVEAU: Initialiser la liste des salons
        roomList.getItems().add("Général"); // Salon par défaut
        roomList.getSelectionModel().selectFirst();
        roomList.setOnMouseClicked(this::handleRoomSelection);
    }

    // NOUVEAU: Gérer le clic sur un salon
    private void handleRoomSelection(MouseEvent event) {
        String selectedRoom = roomList.getSelectionModel().getSelectedItem();
        if (selectedRoom != null && !selectedRoom.equals(currentRoom)) {
            // 1. Demander au client de notifier le serveur qu'on change de salon
            // (La logique de connexion/déconnexion des salons doit être côté Serveur)
            try {
                // Vous devez créer une méthode de commande dans ClientSecureFX (e.g. client.joinRoom(selectedRoom))
                // Pour l'instant, on simule juste le changement

                currentRoom = selectedRoom;
                currentRoomLabel.setText("Salon Actuel : " + currentRoom);
                messageArea.getItems().clear(); // Vider l'historique du chat
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
                // Envoyer une commande au serveur pour créer/rejoindre un salon privé
                // client.requestPrivateRoom(privateUser); <-- Nouvelle méthode à créer

                // Si la création réussit (selon la réponse du serveur)
                Platform.runLater(() -> {
                    if (!roomList.getItems().contains(newRoomName)) {
                        roomList.getItems().add(newRoomName);
                    }
                    roomList.getSelectionModel().select(newRoomName);
                    handleRoomSelection(null); // Force le changement de salon
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
            // MODIFICATION MAJEURE: Préfixer le message avec le nom du salon
            String messageToSend = currentRoom + "|" + message;

            client.sendSecuredMessage(messageToSend); // Le client ajoutera ensuite l'utilisateur et les headers

            // Affichage local immédiat
            displayMessage("Vous (" + currentRoom + "): " + message);
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

    public void setClient(ClientSecureFX client) {
        this.client = client;
    }


}
