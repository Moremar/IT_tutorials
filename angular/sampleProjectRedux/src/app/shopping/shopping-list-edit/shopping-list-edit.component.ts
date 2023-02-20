import { Component, OnInit, OnDestroy, ViewChild } from '@angular/core';
import { NgForm } from '@angular/forms';
import { Subscription } from 'rxjs';
import { Ingredient } from 'src/app/models/ingredient.model';
import { Store } from '@ngrx/store';

import { AddIngredientAction, DeleteIngredientAction, StopEditAction, UpdateIngredientAction } from '../store/shopping-list.actions';
import { ShoppingListState } from '../store/shoppping-list.reducer';
import { AppState } from 'src/app/store/app.reducer';


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


  constructor(
    private store : Store<AppState>
  ) {}

  ngOnInit(): void {
    this.store.select('shoppingList').subscribe(
      (shoppingListStore : ShoppingListState) => {
        this.myEditMode = shoppingListStore.editedIngredient !== null;
        this.myEditedIngredientIndex = shoppingListStore.editedIngredientIndex;
        if (this.myForm && shoppingListStore.editedIngredient) {
          const ingredient = shoppingListStore.ingredients[this.myEditedIngredientIndex];
          this.myForm.setValue({
            ingredientName: shoppingListStore.editedIngredient.name,
            ingredientAmount: shoppingListStore.editedIngredient.amount,
          });
        }
      }
    );
  }

  ngOnDestroy(): void {
    this.myIngredientSelectedSub.unsubscribe();
  }


  onClear() {
    this.store.dispatch(new StopEditAction());
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
    this.store.dispatch(new AddIngredientAction(ingredient));
    this.onClear();
  }

  onUpdateIngredient() {
    const ingredient = new Ingredient(this.myForm.value.ingredientName, Number(this.myForm.value.ingredientAmount));
    this.store.dispatch(new UpdateIngredientAction(ingredient));
    this.onClear();
  }

  onDelete() {
    this.store.dispatch(new DeleteIngredientAction());
    this.onClear();
  }

}
