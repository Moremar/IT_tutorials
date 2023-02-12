import { Component, OnDestroy, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { Subscription } from "rxjs";
import { RecipeService } from 'src/app/services/recipe.service';
import { Recipe } from '../../models/recipe.model';


@Component({
  selector: 'app-recipe-list',
  templateUrl: './recipe-list.component.html',
  styleUrls: ['./recipe-list.component.css']
})
export class RecipeListComponent implements OnInit, OnDestroy {

  myRecipes : Recipe[] = [];
  myRecipesSub : Subscription = null;


  constructor(public recipeService : RecipeService, public router: Router) {}

  ngOnInit(): void {
    this.myRecipes = this.recipeService.getRecipes();
    this.myRecipesSub = this.recipeService.recipesChanged.subscribe(
      (recipes: Recipe[]) => {
        this.myRecipes = recipes;
      }
    );
  }

  ngOnDestroy(): void {
    this.myRecipesSub.unsubscribe();
  }


  onCreateRecipe() {
    this.router.navigate(["recipe", "new"]);
  }

  onLoadSampleRecipes() {
    this.recipeService.loadSampleRecipes();
  }

}
