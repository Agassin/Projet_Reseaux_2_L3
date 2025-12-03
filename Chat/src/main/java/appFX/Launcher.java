package appFX;

import javafx.application.Application;
import javafx.stage.Stage;

public class Launcher extends Application {

    @Override
    public void start(Stage primaryStage) {
        LoginView loginView = new LoginView(primaryStage);
        loginView.show();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
