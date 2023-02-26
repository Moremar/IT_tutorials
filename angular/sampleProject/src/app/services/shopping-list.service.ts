import { Injectable } from '@angular/core';
import { Subject } from 'rxjs';
import { Ingredient } from '../models/ingredient.model';


@Injectable({
  providedIn: 'root'
})
export class ShoppingListService {

  private _ingredients: Ingredient[] = [
    new Ingredient('Chicken', 2),
    new Ingredient('Tomato', 10)
  ];

  // subject triggered after the ingredients are modified
  ingredientsChanged = new Subject<Ingredient[]>();

  // subject triggered when an ingredient is clicked to be edited
  startedEditing = new Subject<number>();


  getIngredients() {
    return this._ingredients.slice();
  }

  getIngredient(i: number) {
    return this._ingredients[i];
  }

  addIngredient(ingredient: Ingredient) {
    console.log('INFO: Adding ingredient :');
    console.log(ingredient);
    // increase the ingredient amount if it is already in the list
    let found = false;
    for (let i = 0; i < this._ingredients.length; i++) {
      if (this._ingredients[i].name == ingredient.name) {
        this._ingredients[i].amount += ingredient.amount;
        found = true;
        break;
      }
    }
    // add the ingredient to the list if it does not exist yet
    if (!found) {
      this._ingredients.push(new Ingredient(ingredient.name, ingredient.amount));
    }
    this.ingredientsChanged.next(this._ingredients.slice());
  }

  updateIngredient(i: number, ingredient: Ingredient) {
    console.log('INFO: Updating ingredient ' + i + ' :');
    console.log(ingredient);
    // replace the edited ingredient
    this._ingredients[i] = ingredient;
    this.ingredientsChanged.next(this._ingredients.slice());
  }

  deleteIngredient(i: number) {
    console.log('INFO: Deleting ingredient ' + i + ' :');
    console.log(this._ingredients[i]);
    this._ingredients.splice(i, 1);
    this.ingredientsChanged.next(this._ingredients.slice());
  }

}
