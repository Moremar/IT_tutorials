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

  myRecipe!: Recipe;
  myRecipeId : number = -1;
  myRouteSub! : Subscription;


  constructor(
    private recipeService : RecipeService,
    private route : ActivatedRoute,
    private router : Router
  ){}

  ngOnInit(): void {
    this.myRouteSub = this.route.params.subscribe(
      (params : Params) => {
        this.myRecipeId = Number(params['id']);
        this.myRecipe = this.recipeService.getRecipe(this.myRecipeId);
      }
    );
  }

  ngOnDestroy(): void {
    // not strictly required, because Angular unsubscribes automatically for ANGULAR subcriptions
    // required for custom subscriptions though (for example to a custom EventEmitter)
    this.myRouteSub.unsubscribe();
  }


  onAddToShoppingList() {
    this.recipeService.addIngredientsToShoppingList(this.myRecipe);
  }

  onEditRecipe() {
    this.router.navigate(['edit'], {relativeTo: this.route});
  }

  onDeleteRecipe() {
    this.recipeService.deleteRecipe(this.myRecipeId);
    this.router.navigate([".."], {relativeTo: this.route});
  }

}
