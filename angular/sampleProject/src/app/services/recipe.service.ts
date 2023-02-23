import { Injectable } from '@angular/core';
import { Subject } from 'rxjs';
import { Ingredient } from '../models/ingredient.model';
import { Recipe } from '../models/recipe.model';
import { ShoppingListService } from "./shopping-list.service";


@Injectable({
  providedIn: 'root'
})
export class RecipeService {

  private _recipes : Recipe[] = [];

  // subject emitting every time the recipes are modified
  recipesChanged = new Subject<Recipe[]>();


  // We can inject a service from another service !
  constructor(public shoppingListService : ShoppingListService) {}


  getRecipe(recipeId : number) {
    // Note that this is the actual recipe
    // if we want to protect it, we can return a clone of that recipe
    return this._recipes[recipeId];
  }

  getRecipes() {
    return this._recipes.slice();
  }

  addIngredientsToShoppingList(recipe : Recipe) {
    for (let i = 0; i < recipe.ingredients.length; i++) {
      this.shoppingListService.addIngredient(recipe.ingredients[i]);
    }
  }

  createRecipe(recipe : Recipe) : number {
    this._recipes.push(recipe);
    this.recipesChanged.next(this._recipes.slice());
    // return the ID of the new recipe
    return this._recipes.length - 1;
  }

  updateRecipe(recipeId : number, recipe : Recipe) {
    this._recipes[recipeId] = recipe;
    this.recipesChanged.next(this._recipes.slice());
  }

  deleteRecipe(recipeId : number) {
    this._recipes.splice(recipeId, 1);
    this.recipesChanged.next(this._recipes.slice());
  }

  loadSampleRecipes() {
    const sampleRecipes : Recipe[] = [
      new Recipe("Roast Chicken",
                 "Garlic Herb Butter Roast Chicken packed with unbelievable flavours, crispy skin, and so juicy!",
                 "https://media.istockphoto.com/id/1317600394/photo/whole-roasted-chicken.jpg?s=612x612&w=0&k=20&c=2Z9NmYoQA2Wrys-EqvjYetVzbRdXdLho1Wbcqbl1PdQ=",
                 [new Ingredient("Chicken", 1), new Ingredient("Potato", 3)]),
      new Recipe("French Fries",
                 "Get the McDonald's–style fries of your dreams at home with this recipe for perfect thin and crispy french fries.",
                 "https://www.healthifyme.com/blog/wp-content/uploads/2022/07/shutterstock_1927479248-1.jpg",
                 [new Ingredient("Potato", 4)]),
      new Recipe("Italian spaghetti",
                 "Best ever spaghetti bolognese is super easy and a true Italian classic with a meaty, chilli sauce.",
                 "https://staticfanpage.akamaized.net/wp-content/uploads/sites/22/2021/06/THUMB-LINK-2020-2-1200x675.jpg",
                 [new Ingredient("Pasta", 1), new Ingredient("Tomato", 2)])
    ];
    this.loadRecipes(sampleRecipes);
  }

  loadRecipes(recipes : Recipe[]) {
    this._recipes = recipes;
    this.recipesChanged.next(this._recipes);
  }

}
