import { Component, OnInit, OnDestroy, ViewChild } from '@angular/core';
import { NgForm } from '@angular/forms';
import { Subscription } from 'rxjs';
import { Ingredient } from 'src/app/models/ingredient.model';
import { ShoppingListService } from 'src/app/services/shopping-list.service';

/**
 * The form in this component is defined with a template-based approach.
 * The NgForm TS object is built by Angular from the HTML template as requested with the
 * <form #myForm="ngForm"> HTML tag.
 * The inputs to include in the TS form object are flagged with the "ngModel" directive.
 *
 * From the TS code, we access this auto-generated TS form object (of class NgForm) using
 * the @ViewChild("myForm") decorator on a NgForm member variable.
 */


@Component({
  selector: 'app-shopping-list-edit',
  templateUrl: './shopping-list-edit.component.html',
  styleUrls: ['./shopping-list-edit.component.css']
})
export class ShoppingListEditComponent implements OnInit, OnDestroy {

  @ViewChild("myForm") myForm! : NgForm;

  myEditMode : boolean = false;
  myEditedIngredientIndex : number = -1;
  myIngredientSelectedSub! : Subscription;


  constructor(private shoppingListService : ShoppingListService) {}

  ngOnInit(): void {
    this.myIngredientSelectedSub = this.shoppingListService.startedEditing.subscribe(
      (i : number) => {
        this.myEditMode = true;
        this.myEditedIngredientIndex = i;
        const ingredient = this.shoppingListService.getIngredient(i);
        this.myForm.setValue({
          ingredientName: ingredient.name,
          ingredientAmount: ingredient.amount,
        });
      }
    );
  }

  ngOnDestroy(): void {
    this.myIngredientSelectedSub.unsubscribe();
  }


  onClear() {
    this.myEditMode = false;
    this.myForm.reset();
  }

  onAddOrUpdateIngredient() {
    if (this.myEditMode) {
      this.onUpdateIngredient();
    } else {
      this.onAddIngredient();
    }
  }

  onAddIngredient() {
    const ingredient = new Ingredient(this.myForm.value.ingredientName, Number(this.myForm.value.ingredientAmount));
    this.shoppingListService.addIngredient(ingredient);
    this.onClear();
  }

  onUpdateIngredient() {
    const ingredient = new Ingredient(this.myForm.value.ingredientName, Number(this.myForm.value.ingredientAmount));
    this.shoppingListService.updateIngredient(this.myEditedIngredientIndex, ingredient);
    this.onClear();
  }

  onDelete() {
    this.shoppingListService.deleteIngredient(this.myEditedIngredientIndex);
    this.onClear();
  }

}
