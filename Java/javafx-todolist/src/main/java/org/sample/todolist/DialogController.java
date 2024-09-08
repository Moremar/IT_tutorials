package org.sample.todolist;

import javafx.fxml.FXML;
import javafx.scene.control.DatePicker;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import org.sample.todolist.datamodel.TodoData;
import org.sample.todolist.datamodel.TodoItem;

import java.time.LocalDate;

public class DialogController {

    @FXML
    private TextField descriptionText;

    @FXML
    private TextArea detailsText;

    @FXML
    private DatePicker dueDatePicker;


    TodoItem processResults() {
        String description = descriptionText.getText().trim();
        String details = detailsText.getText().trim();
        LocalDate dueDate = dueDatePicker.getValue();

        TodoItem newItem = new TodoItem(description, details, dueDate);
        TodoData.getInstance().addTodoItem(newItem);
        return newItem;
    }
}
