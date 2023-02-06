import { Component } from "@angular/core";
import { Ingredient } from "src/app/models/ingredient.model";


@Component({
  selector: 'app-shopping-list',
  templateUrl: 'shopping-list.component.html',
  styleUrls: [ 'shopping-list.component.css']
})
export class ShoppingList {

  ingredients : Ingredient[] = [
    new Ingredient("Apples", 5),
    new Ingredient("Tomatoes", 10)
  ];

  addIngredient(ingredient : Ingredient) {
    this.ingredients.push(ingredient);
  }

  deleteIngredient(ingredient : Ingredient) {
    console.log(ingredient);
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
  }

}
