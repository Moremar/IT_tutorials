import { Component, Input, OnInit } from '@angular/core';
import { Recipe } from 'src/app/models/recipe.model';

@Component({
  selector: 'app-recipe-item',
  templateUrl: './recipe-item.component.html',
  styleUrls: ['./recipe-item.component.css']
})
export class RecipeItemComponent implements OnInit {

  // mandatory inputs
  @Input() recipe!: Recipe;
  @Input() recipeId!: number;

  constructor() {}

  ngOnInit(): void {
    if (this.recipe === undefined) {
      throw new Error("The mandatory 'recipe' @Input is not defined");
    }
    if (this.recipeId === undefined) {
      throw new Error("The mandatory 'recipeId' @Input is not defined");
    }
  }

}
