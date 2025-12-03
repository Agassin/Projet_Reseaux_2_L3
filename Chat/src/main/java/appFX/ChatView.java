package appFX;

import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.input.KeyCode;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;
import javafx.scene.layout.Priority;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class ChatView {
    private Stage primaryStage;
    private ClientSecureFX clientFX;

    private TextArea chatArea;
    private TextField inputField;
    private ListView<String> userList;

    public ChatView(Stage primaryStage, ClientSecureFX clientFX) {
        this.primaryStage = primaryStage;
        this.clientFX = clientFX;
        primaryStage.setTitle("Chat Sécurisé - " + clientFX.getUsername());

        // 1. Zone d'affichage du chat
        chatArea = new TextArea();
        chatArea.setEditable(false);
        chatArea.setWrapText(true);
        VBox chatBox = new VBox(chatArea);
        VBox.setVgrow(chatArea, Priority.ALWAYS);

        // 2. Zone de saisie
        inputField = new TextField();
        inputField.setPromptText("Tapez votre message ici...");
        Button sendButton = new Button("Envoyer");
        sendButton.setDefaultButton(true);
        HBox inputArea = new HBox(5, inputField, sendButton);
        HBox.setHgrow(inputField, Priority.ALWAYS);

        // 3. Liste des utilisateurs
        userList = new ListView<>(clientFX.userList);
        userList.setPrefWidth(150);
        userList.setTooltip(new Tooltip("Double-clic pour un message privé"));

        // Gestion du double-clic pour le MP
        userList.setOnMouseClicked(event -> {
            if (event.getClickCount() == 2 && !userList.getSelectionModel().isEmpty()) {
                String selectedUser = userList.getSelectionModel().getSelectedItem();
                String recipient = selectedUser.replace(" (Moi)", "");
                promptPrivateChat(recipient);
            }
        });

        // 4. Menu
        MenuBar menuBar = createMenuBar();

        // 5. Structure principale (BorderPane)
        BorderPane root = new BorderPane();
        root.setTop(menuBar);

        // Structure centrale avec le chat à gauche et la liste à droite
        HBox centerContent = new HBox(5);
        centerContent.getChildren().addAll(chatBox, userList);
        HBox.setHgrow(chatBox, Priority.ALWAYS);

        root.setCenter(centerContent);
        root.setBottom(inputArea);

        // 6. Gestion des actions
        sendButton.setOnAction(e -> sendMessage());
        inputField.setOnKeyPressed(e -> {
            if (e.getCode() == KeyCode.ENTER) {
                sendMessage();
            }
        });

        // 7. Scène et affichage
        Scene scene = new Scene(root, 800, 600);
        primaryStage.setScene(scene);

        primaryStage.setOnCloseRequest(e -> clientFX.disconnect());
    }

    private MenuBar createMenuBar() {
        MenuBar menuBar = new MenuBar();
        Menu chatMenu = new Menu("Chat");

        MenuItem sendPMItem = new MenuItem("Envoyer Message Privé (Legacy Dialog)");
        sendPMItem.setOnAction(e -> showPrivateMessageDialog());

        MenuItem disconnectItem = new MenuItem("Déconnexion");
        disconnectItem.setOnAction(e -> {
            clientFX.disconnect();
            Platform.exit();
        });

        chatMenu.getItems().addAll(sendPMItem, new SeparatorMenuItem(), disconnectItem);
        menuBar.getMenus().add(chatMenu);
        return menuBar;
    }

    private void showPrivateMessageDialog() {
        Dialog<ButtonType> dialog = new Dialog<>();
        dialog.setTitle("Message Privé Sécurisé");
        dialog.setHeaderText("Envoyer un message chiffré à un autre utilisateur.");

        ButtonType sendButtonType = new ButtonType("Envoyer", ButtonBar.ButtonData.OK_DONE);
        dialog.getDialogPane().getButtonTypes().addAll(sendButtonType, ButtonType.CANCEL);

        GridPane grid = new GridPane();
        grid.setHgap(10);
        grid.setVgap(10);
        grid.setPadding(new Insets(20, 150, 10, 10));

        TextField recipientField = new TextField();
        recipientField.setPromptText("Nom du destinataire");
        TextArea messageArea = new TextArea();
        messageArea.setPromptText("Votre message privé...");
        messageArea.setWrapText(true);

        grid.add(new Label("Destinataire:"), 0, 0);
        grid.add(recipientField, 1, 0);
        grid.add(new Label("Message:"), 0, 1);
        grid.add(messageArea, 1, 1);

        dialog.getDialogPane().setContent(grid);

        Button sendButton = (Button) dialog.getDialogPane().lookupButton(sendButtonType);
        sendButton.disableProperty().bind(recipientField.textProperty().isEmpty().or(messageArea.textProperty().isEmpty()));

        dialog.showAndWait().ifPresent(buttonType -> {
            if (buttonType == sendButtonType) {
                String recipient = recipientField.getText().trim();
                String message = messageArea.getText().trim();
                if (!recipient.isEmpty() && !message.isEmpty()) {
                    try {
                        clientFX.sendPrivateMessage(recipient, message);
                        appendMessage("Système", "Tentative d'envoi MP à " + recipient);
                    } catch (Exception e) {
                        appendMessage("ERREUR", "Échec de l'envoi du MP: " + e.getMessage());
                    }
                }
            }
        });
    }

    private void promptPrivateChat(String recipient) {
        if (recipient.equalsIgnoreCase(clientFX.getUsername())) {
            appendMessage("Système", "Vous ne pouvez pas vous envoyer de MP.");
            return;
        }

        Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
        alert.setTitle("Ouvrir Salon Privé");
        alert.setHeaderText("Démarrer une conversation privée avec " + recipient + "?");
        alert.setContentText("Cliquer OK ouvrira un nouveau salon de discussion chiffré.");

        alert.showAndWait().ifPresent(response -> {
            if (response == ButtonType.OK) {
                try {
                    Stage newStage = new Stage();
                    PrivateChatView privateChat = new PrivateChatView(newStage, clientFX, recipient);
                    clientFX.getPrivateChatWindows().put(recipient, privateChat);
                    privateChat.show();

                } catch (Exception e) {
                    appendMessage("ERREUR", "Impossible d'ouvrir le salon privé: " + e.getMessage());
                }
            }
        });
    }

    private void sendMessage() {
        String message = inputField.getText().trim();
        if (!message.isEmpty()) {
            try {
                clientFX.sendMessage(message);
                appendMessage(clientFX.getUsername() + " (Moi)", message);
                inputField.clear();
            } catch (Exception e) {
                appendMessage("ERREUR", "Échec de l'envoi: " + e.getMessage());
            }
        }
    }

    public void appendMessage(String sender, String message) {
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
        String formattedMessage = String.format("[%s] %s: %s\n", timestamp, sender, message);
        chatArea.appendText(formattedMessage);
    }

    public void show() {
        primaryStage.show();
    }
}