import { Component, Input, OnInit } from '@angular/core';
import { Recipe } from 'src/app/models/recipe.model';

@Component({
  selector: 'app-recipe-details',
  templateUrl: './recipe-details.component.html',
  styleUrls: ['./recipe-details.component.css']
})
export class RecipeDetailsComponent implements OnInit {

  @Input() recipe: Recipe;

  constructor() {}

  ngOnInit(): void {}

  onAddToShoppingList() {
    alert("TODO : Add to shopping list!");
  }

  onEditRecipe() {
    alert("TODO : Edit Recipe!");
  }

  onDeleteRecipe() {
    alert("TODO : Delete Recipe!");
  }
}
