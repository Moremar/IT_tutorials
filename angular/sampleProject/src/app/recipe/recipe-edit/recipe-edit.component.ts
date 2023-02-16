import { Component, OnInit } from '@angular/core';
import { FormArray, FormControl, FormGroup, Validators } from '@angular/forms';
import { ActivatedRoute, Params, Router } from '@angular/router';
import { Ingredient } from 'src/app/models/ingredient.model';
import { Recipe } from 'src/app/models/recipe.model';
import { RecipeService } from 'src/app/services/recipe.service';

/**
 * This recipe edition/creation form is created using the reactive approach.
 * This is requried to have a dynamic array of form controls for the ingredients.
 *
 * The structure of the TS form object (of type FormGroup) is defined in the TS code,
 * and is linked to the HTML <form> tag using [formGroup]="myForm".
 * Each form group, form control or form array in the TS object must be linked to the HTML
 * corresponding tag with the formGroupName/formControlName/formArrayName directive.
 */


@Component({
  selector: 'app-recipe-edit',
  templateUrl: './recipe-edit.component.html',
  styleUrls: ['./recipe-edit.component.css']
})
export class RecipeEditComponent implements OnInit {

  myForm! : FormGroup;
  myRecipe : Recipe | null = null;
  myRecipeId : number = -1;
  myEditMode : boolean = false;

  // getter function to get the controls of the ingredients array
  // this logic does not work if inserted directly in the template
  get ingredientControls() {
    return (<FormArray>this.myForm.get('recipeIngredients')).controls;
  }


  constructor(
    private route : ActivatedRoute,
    private router : Router,
    private recipeService : RecipeService
  ) {}

  ngOnInit(): void {
    this.route.params.subscribe(
      (params : Params) => {
        this.myEditMode = 'id' in params;
        this.myRecipeId = this.myEditMode ? Number(params['id']) : -1;
        this.myRecipe   = this.myEditMode ? this.recipeService.getRecipe(this.myRecipeId) : null;
        this.initForm();
      }
    );
  }


  initForm() {
    // define the form structure and initial values
    const recipeName        = this.myEditMode ? this.myRecipe!.name : '';
    const recipeImageUrl    = this.myEditMode ? this.myRecipe!.imageUrl : '';
    const recipeDescription = this.myEditMode ? this.myRecipe!.description : '';
    let recipeIngredientsArr = new FormArray<FormGroup>([]);
    if (this.myEditMode) {
      for (let ingredient of this.myRecipe!.ingredients) {
        recipeIngredientsArr.push(new FormGroup({
          'ingredientName': new FormControl(ingredient.name, Validators.required),
          'ingredientAmount': new FormControl(ingredient.amount, [Validators.required, Validators.pattern('^[1-9][0-9]*$')]),
        }));
      }
    }

    this.myForm = new FormGroup({
      'recipeName': new FormControl(recipeName, Validators.required),
      'recipeImageUrl': new FormControl(recipeImageUrl, Validators.required),
      'recipeDescription': new FormControl(recipeDescription, Validators.required),
      'recipeIngredients': recipeIngredientsArr
    });
  }

  onSubmit() {
    // create the Recipe object
    let ingredients = [];
    for (let ingredient of this.myForm.value.recipeIngredients) {
      ingredients.push(new Ingredient(ingredient.ingredientName, ingredient.ingredientAmount));
    }
    const recipe = new Recipe(
      this.myForm.value.recipeName,
      this.myForm.value.recipeDescription,
      this.myForm.value.recipeImageUrl,
      ingredients
    );
    // create or update the recipe
    if (this.myEditMode) {
      this.updateRecipe(recipe);
    } else {
      this.createRecipe(recipe);
    }
  }

  createRecipe(recipe : Recipe) {
    const recipeId = this.recipeService.createRecipe(recipe);
    // leave the edit mode
    this.router.navigate(['..', recipeId], {relativeTo: this.route});
  }

  updateRecipe(recipe : Recipe) {
    this.recipeService.updateRecipe(this.myRecipeId, recipe);
    // leave the edit mode
    this.router.navigate(['..'], {relativeTo: this.route});
  }

  onCancel() {
    // navigate back to the details of this recipe
    this.router.navigate(['..'], {relativeTo: this.route});
  }

  onAddIngredientToRecipe() {
    (<FormArray>this.myForm.controls['recipeIngredients']).push(
      new FormGroup({
        'ingredientName': new FormControl(null, Validators.required),
        'ingredientAmount': new FormControl(null, [Validators.required, Validators.pattern('^[1-9][0-9]*$')])
      })
    );
  }

  onDeleteIngredientFromRecipe(i: number) {
    (<FormArray>this.myForm.controls['recipeIngredients']).removeAt(i);
  }

}
