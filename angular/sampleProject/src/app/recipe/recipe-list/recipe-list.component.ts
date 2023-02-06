import { Component, EventEmitter, Input, OnInit, Output } from '@angular/core';
import { Recipe } from '../../models/recipe.model';

@Component({
  selector: 'app-recipe-list',
  templateUrl: './recipe-list.component.html',
  styleUrls: ['./recipe-list.component.css']
})
export class RecipeListComponent implements OnInit {

  @Input() recipes : Recipe[] = [];
  @Output() recipeSelected = new EventEmitter<Recipe>();

  constructor() {}

  ngOnInit(): void {}

  onCreateRecipe() {
    alert("TODO : Create recipe");
  }

  onItemClicked(recipe: Recipe) {
    this.recipeSelected.emit(recipe);
  }
}
