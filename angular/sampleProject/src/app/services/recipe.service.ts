import { EventEmitter, Injectable } from '@angular/core';
import { Ingredient } from '../models/ingredient.model';
import { Recipe } from '../models/recipe.model';
import { ShoppingListService } from "./shopping-list.service";


@Injectable({
  providedIn: 'root'
})
export class RecipeService {

  private recipes : Recipe[] = [
    new Recipe("Roast Chicken", "Garlic Herb Butter Roast Chicken packed with unbelievable flavours, crispy skin, and so juicy!", "https://media.istockphoto.com/id/1317600394/photo/whole-roasted-chicken.jpg?s=612x612&w=0&k=20&c=2Z9NmYoQA2Wrys-EqvjYetVzbRdXdLho1Wbcqbl1PdQ=",
        [new Ingredient("Chicken", 1), new Ingredient("Potato", 3)]),
    new Recipe("French Fries", "Get the McDonald's–style fries of your dreams at home with this recipe for perfect thin and crispy french fries.", "https://www.healthifyme.com/blog/wp-content/uploads/2022/07/shutterstock_1927479248-1.jpg",
        [new Ingredient("Potato", 4)]),
    new Recipe("Italian spaguetti", "Best ever spaghetti bolognese is super easy and a true Italian classic with a meaty, chilli sauce.", "https://staticfanpage.akamaized.net/wp-content/uploads/sites/22/2021/06/THUMB-LINK-2020-2-1200x675.jpg",
        [new Ingredient("Pasta", 1), new Ingredient("Tomato", 2)])
  ];

  private selectedRecipe : Recipe = this.recipes[0];
  selectedRecipeChanged = new EventEmitter<Recipe>();


  // We can inject a service from another service !
  constructor(public shoppingListService : ShoppingListService) {}

  getRecipes() {
    return this.recipes.slice();
  }

  getSelectedRecipe() {
    return this.selectedRecipe;
  }

  setSelectedRecipe(recipeId : number) {
    this.selectedRecipe = this.recipes[recipeId];
    this.selectedRecipeChanged.emit(this.selectedRecipe);
  }

  addIngredientsToShoppingList(recipe : Recipe) {
    for (let i = 0; i < recipe.ingredients.length; i++) {
      this.shoppingListService.addIngredient(recipe.ingredients[i]);
    }
  }
}
