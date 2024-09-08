package org.sample.todolist;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;
import org.sample.todolist.datamodel.TodoData;

import java.io.IOException;


public class TodoListApplication extends Application {
    @Override
    public void start(Stage stage) throws IOException {
        // use the CASPIAN CSS theme
        setUserAgentStylesheet(STYLESHEET_CASPIAN);

        // load the FXML content into a parent node
        FXMLLoader fxmlLoader = new FXMLLoader(TodoListApplication.class.getResource("todolist-view.fxml"));
        Parent root = fxmlLoader.load();

        // create a scene containing the node loaded from FXML
        Scene scene = new Scene(root, 700, 600);

        // prepare and show the stage
        stage.setTitle("Hello!");
        stage.setScene(scene);
        stage.show();
    }

    @Override
    public void init() {
        try {
            TodoData.getInstance().loadTodoItems();
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
    }

    @Override
    public void stop() throws Exception {
        try {
            TodoData.getInstance().storeTodoItems();
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
        super.stop();
    }

    public static void main(String[] args) {
        launch();
    }
}