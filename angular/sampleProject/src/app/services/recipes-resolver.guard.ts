import { Injectable } from '@angular/core';
import { ActivatedRouteSnapshot, RouterStateSnapshot, Resolve } from '@angular/router';
import { Observable } from 'rxjs';
import { Recipe } from '../models/recipe.model';
import { DataStorageService } from './data-storage.service';
import { RecipeService } from './recipe.service';

/**
 * Resolver guard preventing the case where we request the edit page URL of a recipe that is not loaded yet.
 * When we request a route on a specific recipe ID, this resolver will check if there are recipes in the recipe service.
 * If there are not, it will load the recipes from the backend before letting the route resolve.
 */


@Injectable({
  providedIn: 'root'
})
export class RecipesResolverGuard implements Resolve<Recipe[]> {

  constructor(
    private dataStorageService: DataStorageService,
    private recipeService: RecipeService
  ) {}

  resolve(route: ActivatedRouteSnapshot, state: RouterStateSnapshot): Recipe[] | Observable<Recipe[]> | Promise<Recipe[]> {
    // return the Observable on recipes if recipes are not loaded yet
    const recipes = this.recipeService.getRecipes();
    if (recipes.length === 0) {
      return this.dataStorageService.loadRecipesFromBackend();
    }
    // if recipes are already loaded, return them (result not used, the resolver only ensures there are recipes)
    return recipes;
  }

}
