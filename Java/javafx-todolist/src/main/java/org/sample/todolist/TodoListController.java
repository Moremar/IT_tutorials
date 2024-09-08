package org.sample.todolist;

import javafx.application.Platform;
import javafx.collections.transformation.FilteredList;
import javafx.collections.transformation.SortedList;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.control.*;
import javafx.scene.input.KeyCode;
import javafx.scene.input.KeyEvent;
import javafx.scene.layout.BorderPane;
import javafx.scene.paint.Color;
import javafx.util.Callback;
import org.sample.todolist.datamodel.TodoData;
import org.sample.todolist.datamodel.TodoItem;

import java.io.IOException;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Comparator;


public class TodoListController {

    @FXML
    private BorderPane mainBorderPane;

    @FXML
    private ListView<TodoItem> todoListView;

    @FXML
    private TextArea detailsTextArea;

    @FXML
    private Label deadlineLabel;

    @FXML
    private ContextMenu listContextMenu;

    @FXML
    private ToggleButton onlyDueToggleButton;

    // underlying observable collection used by the list view
    // to display all the TodoItem objects
    FilteredList<TodoItem> filteredList;

    @FXML
    public void initialize() {
        // create a context menu that will be added to all cells in the list view
        listContextMenu = new ContextMenu();
        MenuItem deleteMenuItem = new MenuItem("Delete");
        deleteMenuItem.setOnAction(event -> {
            TodoItem item = todoListView.getSelectionModel().getSelectedItem();
            deleteItem(item);
        });
        listContextMenu.getItems().addAll(deleteMenuItem);

        // define an event handler programmatically, so it covers not only click on an item
        // but any change of selected value in the listView that would be done by code
        // when an item is selected, we update the main area with this item details
        todoListView.getSelectionModel().selectedItemProperty().addListener(
            (observableValue, oldVal, newVal) -> {
                if (newVal != null) {
                    TodoItem item = todoListView.getSelectionModel().getSelectedItem();
                    detailsTextArea.setText(item.details());
                    DateTimeFormatter df = DateTimeFormatter.ofPattern("MMMM d, yyyy");
                    deadlineLabel.setText(df.format(item.deadline()));
                }
            }
        );

        // set the cell factory deciding how each cell in the list view is generated
        todoListView.setCellFactory(new Callback<>() {
            @Override
            public ListCell<TodoItem> call(ListView<TodoItem> todoItemListView) {
                ListCell<TodoItem> cell = new ListCell<>() {
                    // method to decide what is displayed inside each cell
                    @Override
                    protected void updateItem(TodoItem item, boolean empty) {
                        super.updateItem(item, empty);
                        if (empty) {
                            setText(null);
                        } else {
                            setText(item.description());
                            if (item.deadline().isBefore(LocalDate.now())) {
                                setTextFill(Color.RED);
                            }
                        }
                    }
                };
                // set the context menu to non-empty cells
                // we associate the listener to the empty property so we add a listener
                // when the cell becomes non-empty
                cell.emptyProperty().addListener(
                        (obs, wasEmpty, isNowEmpty) -> {
                            if (isNowEmpty) {
                                // empty cells have no context menu
                                cell.setContextMenu(null);
                            } else {
                                cell.setContextMenu(listContextMenu);
                            }
                        }
                );
                return cell;
            }
        });

        // instead of using the observable list as underlying list, we wrap it
        // in a JavaFX FilteredList, then a JavaFX SortedList, so it keeps it filtered and sorted
        filteredList = new FilteredList<>(
                TodoData.getInstance().getTodoItems(),
                item -> true );
        SortedList<TodoItem> sortedList = new SortedList<>(
                filteredList,
                Comparator.comparing(TodoItem::deadline) );

        todoListView.setItems(sortedList);
        todoListView.getSelectionModel().setSelectionMode(SelectionMode.SINGLE);

        // select the first item of the list by default
        todoListView.getSelectionModel().selectFirst();
    }

    @FXML
    public void handleKeyPressed(KeyEvent event) {
        // in addition to the Delete menu item in the context menu, we want to also
        // allow the user to delete the selected TodoItem by pressing the Delete key
        if (event.getCode().equals(KeyCode.DELETE)) {
            TodoItem item = todoListView.getSelectionModel().getSelectedItem();
            if (item != null) {
                deleteItem(item);
            }
        }
    }

    @FXML
    public void showNewItemDialog() {
        // instantiate the Dialog object
        Dialog<ButtonType> dialog = new Dialog<>();
        dialog.setTitle("Todo Item Creation");
        dialog.initOwner(mainBorderPane.getScene().getWindow());

        // set the loader for the dialog fxml
        FXMLLoader fxmlLoader = new FXMLLoader();
        fxmlLoader.setLocation(getClass().getResource("todoItemDialog.fxml"));
        try {
            dialog.getDialogPane().setContent(fxmlLoader.load());
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }

        // set the buttons that the DialogPane should contain
        dialog.getDialogPane().getButtonTypes().add(ButtonType.OK);
        dialog.getDialogPane().getButtonTypes().add(ButtonType.CANCEL);

        // open the Dialog and wait for its result synchronously
        dialog.showAndWait().ifPresent(response -> {
           if (response == ButtonType.OK) {
               DialogController controller = fxmlLoader.getController();
               TodoItem newItem = controller.processResults();
               todoListView.getSelectionModel().select(newItem);
            }
        });
    }

    private void deleteItem(TodoItem item) {
        // open a confirmation popup for deletion
        Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
        alert.setTitle("Delete Todo Item");
        alert.setHeaderText("Delete item: " + item.description());
        alert.setContentText("Are you sure ?");
        alert.showAndWait().ifPresent(
            result -> {
                if (result == ButtonType.OK) {
                    TodoData.getInstance().deleteTodoItem(item);
                }
            }
        );
    }

    @FXML
    public void handleToggleChange() {
        // get the selected item
        TodoItem selectedItem = todoListView.getSelectionModel().getSelectedItem();
        // update the filter predicate so the list is re-filtered
        filteredList.setPredicate(item -> !onlyDueToggleButton.isSelected()
                                       || item.deadline().isBefore(LocalDate.now()));
        // re-select the item if still there, else select the first item
        if (todoListView.getItems().contains(selectedItem)) {
            todoListView.getSelectionModel().select(selectedItem);
        } else {
            todoListView.getSelectionModel().selectFirst();
        }
    }

    @FXML
    public void handleExit() {
        // close the application when the user clicks Exit in the menu bar
        Platform.exit();
    }
}