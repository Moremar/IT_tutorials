package org.sample.todolist.datamodel;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;

/**
 * Singleton class, to have a quick way to share data between
 * the Main class and the controller
 */
public class TodoData {
    private static final TodoData instance = new TodoData();
    private static final String fileName = "TodoListItems.txt";

    private ObservableList<TodoItem> todoItems;
    private final DateTimeFormatter formatter;

    public static TodoData getInstance() {
        return instance;
    }

    private TodoData() {
        // initialize the date formatter
        formatter = DateTimeFormatter.ofPattern("dd-MM-yyyy");
    }

    public ObservableList<TodoItem> getTodoItems() {
        return todoItems;
    }

    public void addTodoItem(TodoItem item) {
        todoItems.add(item);
    }

    public void deleteTodoItem(TodoItem item) {
        todoItems.remove(item);
    }

    public void loadTodoItems() throws IOException {
        // basic serialization by reading each item as a tab-separated file
        todoItems = FXCollections.observableArrayList();
        Path path = Paths.get(fileName);
        try (BufferedReader reader = Files.newBufferedReader(path)) {
            String input;
            while ((input = reader.readLine()) != null) {
                String[] itemPieces = input.split("\t");
                String description = itemPieces[0];
                String details = itemPieces[1];
                String dateString = itemPieces[2];
                LocalDate date = LocalDate.parse(dateString, formatter);

                TodoItem todoItem = new TodoItem(description, details, date);
                todoItems.add(todoItem);
            }
        }
    }

    public void storeTodoItems() throws IOException {
        // basic serialization by writing each item to a tab-separated file
        Path path = Paths.get(fileName);
        try (BufferedWriter writer = Files.newBufferedWriter(path)) {
            for (TodoItem todoItem : todoItems) {
                writer.write(String.format("%s\t%s\t%s",
                        todoItem.description(),
                        todoItem.details(),
                        todoItem.deadline().format(formatter)));
                writer.newLine();
            }
        }
    }
}
