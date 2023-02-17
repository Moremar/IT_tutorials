import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { map, tap } from 'rxjs/operators';
import { RecipeService } from './recipe.service';
import { Recipe } from '../models/recipe.model';
import { environment } from '../../environments/environment';
import { Ingredient } from '../models/ingredient.model';

/**
 * This service handles the storage and retrieval of recipes from the Firebase backend.
 * Ingredients are not saved in the backend for this sample projects.
 * It could be part of the recipe service, especially if we wanted to sync the backend
 * everytime we create/update/delete a recipe.
 *
 * In this sample app, we only interact with the backend when clicking the Save or Load
 * buttons in the header navbar, so only this service uses the HTTP client.
 */


@Injectable({
  providedIn: 'root'
})
export class DataStorageService {

  readonly BACKEND_URL : string = environment.firebase.db_url  + '/recipes.json';

  constructor(
    private http : HttpClient,
    public recipeService : RecipeService
  ) {}


  saveRecipesToBackend() {
    // no user of this method cares about the result of the HTTP request, so we
    // subscribe from this method
    const recipes : Recipe[] = this.recipeService.getRecipes();
    this.http
      .put<Recipe[]>(this.BACKEND_URL, recipes)
      .subscribe(
        (responseData : Recipe[]) => {
          console.log("Recipes saved in the backend.");
          console.log(responseData);
        }
      );
  }

  loadRecipesFromBackend() : Observable<Recipe[]> {
    // we do not subscribe from this method when a user of this method (for example a component)
    // cares about the response and needs to sbscribe to update the GUI (adding a spinner for ex),
    // or when a user (for example a resolve guard in this case) needs to get the observable.
     return this.http
      .get<Recipe[]>(this.BACKEND_URL)
      .pipe(
        // recipes with no ingredients will not have an "ingredients" property in Firebase
        // here we add an empty Ingredient[] in recipes where this property is missing
        // we also convert the amount of ingredients to numbers (they are stored as strings in Firebase)
        map(
          (responseData) => {
            return responseData.map(
              (recipe) => {
                let ingredients : Ingredient[] = [];
                for (let ingredient of recipe.ingredients) {
                  ingredients.push(new Ingredient(ingredient.name, Number(ingredient.amount)));
                }
                return new Recipe(recipe.name, recipe.description, recipe.imageUrl, ingredients);
              }
            );
          }
        ),
        // everytime we fetch the data, replace the current recipes in the recipe service
        tap(
          (recipes : Recipe[]) => {
            this.recipeService.loadRecipes(recipes);
          }
        )
      );
  }

}
