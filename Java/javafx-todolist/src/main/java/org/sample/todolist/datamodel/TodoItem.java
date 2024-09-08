package org.sample.todolist.datamodel;

import java.time.LocalDate;

public record TodoItem(String description, String details, LocalDate deadline) {
}
