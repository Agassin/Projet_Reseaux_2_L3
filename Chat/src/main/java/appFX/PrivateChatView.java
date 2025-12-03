package appFX;

import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.input.KeyCode;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class PrivateChatView {
    private final Stage stage;
    private final ClientSecureFX clientFX;
    private final String recipient;

    private TextArea chatArea;
    private TextField inputField;

    public PrivateChatView(Stage stage, ClientSecureFX clientFX, String recipient) {
        this.stage = stage;
        this.clientFX = clientFX;
        this.recipient = recipient;

        stage.setTitle("MP Chiffré avec " + recipient);

        // 1. Zone d'affichage du chat
        chatArea = new TextArea();
        chatArea.setEditable(false);
        chatArea.setWrapText(true);
        VBox.setVgrow(chatArea, Priority.ALWAYS);

        // 2. Zone de saisie
        inputField = new TextField();
        inputField.setPromptText("Message à " + recipient + "...");
        Button sendButton = new Button("Envoyer");
        sendButton.setDefaultButton(true);
        HBox inputArea = new HBox(5, inputField, sendButton);
        HBox.setHgrow(inputField, Priority.ALWAYS);

        // 3. Contenu principal
        VBox root = new VBox(10, chatArea, inputArea);
        root.setPadding(new Insets(10));
        VBox.setVgrow(chatArea, Priority.ALWAYS);

        // 4. Gestion des actions
        sendButton.setOnAction(e -> sendMessage());
        inputField.setOnKeyPressed(e -> {
            if (e.getCode() == KeyCode.ENTER) {
                sendMessage();
            }
        });

        // Gestion de la fermeture
        stage.setOnCloseRequest(e -> clientFX.closePrivateChat(recipient));

        // 5. Scène
        Scene scene = new Scene(root, 400, 400);
        stage.setScene(scene);

        appendMessage("Système", "Salon privé sécurisé démarré.");
    }

    private void sendMessage() {
        String message = inputField.getText().trim();
        if (!message.isEmpty()) {
            try {
                clientFX.sendPrivateMessage(recipient, message);
                appendMessage(clientFX.getUsername() + " (Moi)", message);
                inputField.clear();
            } catch (Exception e) {
                appendMessage("ERREUR", "Échec de l'envoi du MP: " + e.getMessage());
            }
        }
    }

    public void appendMessage(String sender, String message) {
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
        String formattedMessage = String.format("[%s] %s: %s\n", timestamp, sender, message);
        chatArea.appendText(formattedMessage);
    }

    public void show() {
        stage.show();
    }
}
