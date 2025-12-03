package appFX;

import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

public class LoginView {

    private final Stage primaryStage;
    private final TextField usernameField;
    private final TextField hostField;
    private final TextField portField;
    private final Label statusLabel;
    private final Button connectButton;

    public LoginView(Stage primaryStage) {
        this.primaryStage = primaryStage;
        primaryStage.setTitle("Chat Sécurisé FX - Connexion");

        usernameField = new TextField("userFX");
        usernameField.setPromptText("Nom d'utilisateur");

        hostField = new TextField("localhost");
        hostField.setPromptText("Hôte");

        portField = new TextField("5000");
        portField.setPromptText("Port");

        connectButton = new Button("Se Connecter");
        connectButton.setPrefWidth(Double.MAX_VALUE);
        connectButton.setOnAction(e -> handleConnect());

        statusLabel = new Label("Prêt à se connecter.");
        statusLabel.setStyle("-fx-text-fill: gray;");

        GridPane grid = new GridPane();
        grid.setAlignment(Pos.CENTER);
        grid.setHgap(10);
        grid.setVgap(10);
        grid.setPadding(new Insets(25, 25, 25, 25));

        grid.add(new Label("Utilisateur:"), 0, 0);
        grid.add(usernameField, 1, 0);
        grid.add(new Label("Hôte:"), 0, 1);
        grid.add(hostField, 1, 1);
        grid.add(new Label("Port:"), 0, 2);
        grid.add(portField, 1, 2);

        VBox root = new VBox(20);
        root.setAlignment(Pos.CENTER);
        root.setPadding(new Insets(30));
        root.getChildren().addAll(grid, connectButton, statusLabel);

        Scene scene = new Scene(root, 400, 350);
        primaryStage.setScene(scene);
        primaryStage.setResizable(false);
    }

    public void show() {
        primaryStage.show();
    }

    private void handleConnect() {
        String username = usernameField.getText().trim();
        int port;
        try {
            port = Integer.parseInt(portField.getText().trim());
        } catch (NumberFormatException e) {
            statusLabel.setText("Erreur: Port invalide.");
            statusLabel.setStyle("-fx-text-fill: red;");
            return;
        }

        if (username.isEmpty()) {
            statusLabel.setText("Erreur: Le nom d'utilisateur est requis.");
            statusLabel.setStyle("-fx-text-fill: red;");
            return;
        }

        statusLabel.setText("Tentative de connexion...");
        statusLabel.setStyle("-fx-text-fill: orange;");
        connectButton.setDisable(true);

        new Thread(() -> {
            ClientSecureFX clientFX = null;
            try {
                // Création de l'instance ClientSecureFX (inclut la génération de clés)
                clientFX = new ClientSecureFX(username, null); // ChatView est initialisée plus tard

                // Connexion et Authentification
                clientFX.startConnection();

                final ClientSecureFX finalClient = clientFX;

                // Si succès, passe au chat (doit se faire sur le thread JavaFX)
                javafx.application.Platform.runLater(() -> {
                    try {
                        ChatView chatView = new ChatView(primaryStage, finalClient);
                        finalClient.setChatView(chatView); // Assigne la vue après création
                        chatView.show();
                    } catch (Exception e) {
                        e.printStackTrace();
                        statusLabel.setText("Erreur interne du chat: " + e.getMessage());
                        statusLabel.setStyle("-fx-text-fill: red;");
                    }
                });

            } catch (Exception e) {
                if (clientFX != null) clientFX.disconnect();

                javafx.application.Platform.runLater(() -> {
                    String errorMsg = (e.getMessage() != null) ? e.getMessage() : "Erreur inconnue.";
                    statusLabel.setText("Échec de la connexion/Auth: " + errorMsg);
                    statusLabel.setStyle("-fx-text-fill: red;");
                    connectButton.setDisable(false);
                });
            }
        }).start();
    }
}