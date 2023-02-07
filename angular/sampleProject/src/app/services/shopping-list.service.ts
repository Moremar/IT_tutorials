import { EventEmitter, Injectable } from '@angular/core';
import { Ingredient } from '../models/ingredient.model';


@Injectable({
  providedIn: 'root'
})
export class ShoppingListService {

  private ingredients : Ingredient[] = [
    new Ingredient("Chicken", 2),
    new Ingredient("Tomato", 10)
  ];
  ingredientsChanged = new EventEmitter<Ingredient[]>();


  constructor() {}

  getIngredients() {
    return this.ingredients.slice();
  }

  addIngredient(ingredient : Ingredient) {
    // increase the ingredient amount if it is already in the list
    for (let i = 0; i < this.ingredients.length; i++) {
      if (this.ingredients[i].name == ingredient.name) {
        this.ingredients[i].amount += ingredient.amount;
        return;
      }
    }
    // add the ingredient to the list if it does not exist yet
    this.ingredients.push(ingredient);
    this.ingredientsChanged.emit(this.ingredients.slice());
  }

  deleteIngredient(ingredient : Ingredient) {
    for (let i = 0; i < this.ingredients.length; i++) {
      if (this.ingredients[i].name == ingredient.name) {
        if (this.ingredients[i].amount > ingredient.amount) {
          this.ingredients[i].amount -= ingredient.amount;
        } else {
          this.ingredients.splice(i, 1);
        }
        break;
      }
    }
    this.ingredientsChanged.emit(this.ingredients.slice());
  }
}
