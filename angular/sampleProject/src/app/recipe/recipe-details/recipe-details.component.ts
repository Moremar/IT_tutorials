import { Component, OnInit, OnDestroy } from '@angular/core';
import { Subscription } from 'rxjs';
import { Recipe } from 'src/app/models/recipe.model';
import { RecipeService } from 'src/app/services/recipe.service';

@Component({
  selector: 'app-recipe-details',
  templateUrl: './recipe-details.component.html',
  styleUrls: ['./recipe-details.component.css']
})
export class RecipeDetailsComponent implements OnInit, OnDestroy {

  recipe: Recipe;
  private recipeSubscription : Subscription;

  constructor(public recipeService : RecipeService) {}

  ngOnInit(): void {
    this.recipe = this.recipeService.getSelectedRecipe();
    this.recipeSubscription = this.recipeService.selectedRecipeChanged.subscribe(
      (selectedRecipe : Recipe) => {
        this.recipe = selectedRecipe;
      }
    );
  }

  ngOnDestroy(): void {
    this.recipeSubscription.unsubscribe();
  }

  onAddToShoppingList() {
    this.recipeService.addIngredientsToShoppingList(this.recipe);
  }

  onEditRecipe() {
    alert("TODO : Edit Recipe!");
  }

  onDeleteRecipe() {
    alert("TODO : Delete Recipe!");
  }
}
