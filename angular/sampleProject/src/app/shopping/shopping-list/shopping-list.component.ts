import { Component, OnInit, OnDestroy } from "@angular/core";
import { Subscription } from "rxjs";
import { Ingredient } from "src/app/models/ingredient.model";
import { ShoppingListService } from "src/app/services/shopping-list.service";


@Component({
  selector: 'app-shopping-list',
  templateUrl: 'shopping-list.component.html',
  styleUrls: [ 'shopping-list.component.css']
})
export class ShoppingList implements OnInit, OnDestroy {

  ingredients : Ingredient[] = [];
  private ingredientsSubscription : Subscription;


  constructor(public shoppingListService : ShoppingListService) {}

  ngOnInit(): void {
    this.ingredients = this.shoppingListService.getIngredients();
    this.ingredientsSubscription = this.shoppingListService.ingredientsChanged.subscribe(
      (ingredientsList : Ingredient[]) => {
        this.ingredients = ingredientsList;
      }
    );
  }

  ngOnDestroy(): void {
    this.ingredientsSubscription.unsubscribe();
  }

  addIngredient(ingredient : Ingredient) {
    this.shoppingListService.addIngredient(ingredient);
  }

  deleteIngredient(ingredient : Ingredient) {
    this.shoppingListService.deleteIngredient(ingredient);
  }
}
