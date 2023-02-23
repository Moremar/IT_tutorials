import { Component, OnDestroy, OnInit } from '@angular/core';
import { Subscription } from 'rxjs';
import { Recipe } from '../models/recipe.model';
import { RecipeService } from '../services/recipe.service';

@Component({
  selector: 'app-component-for-test',
  templateUrl: './component-for-test.component.html',
  styleUrls: ['./component-for-test.component.css']
})
export class ComponentForTestComponent implements OnInit, OnDestroy {

  myRecipes : Recipe[] = [];
  private myRecipeSub! : Subscription;

  constructor(
    private recipeService : RecipeService
  ) {}

  ngOnInit(): void {
    this.myRecipeSub = this.recipeService.recipesChanged.subscribe(
      (recipes : Recipe[]) => {
        this.myRecipes = recipes;
      }
    );
  }

  ngOnDestroy(): void {
      this.myRecipeSub.unsubscribe();
  }

}
