import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Params } from '@angular/router';
import { Recipe } from 'src/app/models/recipe.model';
import { RecipeService } from 'src/app/services/recipe.service';

@Component({
  selector: 'app-recipe-edit',
  templateUrl: './recipe-edit.component.html',
  styleUrls: ['./recipe-edit.component.css']
})
export class RecipeEditComponent implements OnInit {

  recipe : Recipe = null;
  recipeId : number = -1;
  editMode : boolean = false;

  constructor(
    public route : ActivatedRoute,
    public recipeService : RecipeService
  ) {}

  ngOnInit(): void {
    this.route.params.subscribe(
      (params : Params) => {
        this.editMode = 'id' in params;
        this.recipeId = this.editMode ? Number(params.id) : -1;
        this.recipe   = this.editMode ? this.recipeService.getRecipe(this.recipeId) : null;
      }
    );
  }

}
