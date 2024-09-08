module org.sample.todolist {
    requires javafx.controls;
    requires javafx.fxml;
    requires java.desktop;


    opens org.sample.todolist to javafx.fxml;
    exports org.sample.todolist;
}