import { Component, EventEmitter, OnInit, Output } from '@angular/core';
import { Ingredient } from 'src/app/models/ingredient.model';

@Component({
  selector: 'app-shopping-list-edit',
  templateUrl: './shopping-list-edit.component.html',
  styleUrls: ['./shopping-list-edit.component.css']
})
export class ShoppingListEditComponent implements OnInit {

  @Output() ingredientAdded = new EventEmitter<Ingredient>();
  @Output() ingredientDeleted = new EventEmitter<Ingredient>();

  constructor() {}

  ngOnInit(): void {}

  onClear(nameInput : HTMLInputElement, amountInput : HTMLInputElement) {
    nameInput.value = "";
    amountInput.value = "";
  }

  onAdd(nameInput : HTMLInputElement, amountInput : HTMLInputElement) {
    let ingredient = new Ingredient(nameInput.value, Number(amountInput.value));
    this.ingredientAdded.emit(ingredient);
  }

  onDelete(nameInput : HTMLInputElement, amountInput : HTMLInputElement) {
    let ingredient = new Ingredient(nameInput.value, Number(amountInput.value));
    this.ingredientDeleted.emit(ingredient);
  }
}
