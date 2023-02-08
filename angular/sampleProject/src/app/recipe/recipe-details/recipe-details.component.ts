import { Component, OnInit, OnDestroy } from '@angular/core';
import { ActivatedRoute, Params, Router } from '@angular/router';
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
  private routeSub : Subscription;

  constructor(
    public recipeService : RecipeService,
    public route : ActivatedRoute,
    public router : Router
  ){}

  ngOnInit(): void {
    this.routeSub = this.route.params.subscribe(
      (params : Params) => {
        this.recipe = this.recipeService.getRecipe(Number(params.id));
      }
    );
  }

  ngOnDestroy(): void {
    // not strictly required, because Angular unsubscribes automatically for ANGULAR subcriptions
    // required for custom subscriptions though (for example to a custom EventEmitter)
    this.routeSub.unsubscribe();
  }

  onAddToShoppingList() {
    this.recipeService.addIngredientsToShoppingList(this.recipe);
  }

  onEditRecipe() {
    this.router.navigate(['edit'], {relativeTo: this.route});
  }

  onDeleteRecipe() {
    alert("TODO : Delete Recipe!");
  }
}
