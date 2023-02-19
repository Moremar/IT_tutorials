import { Component, OnInit, OnDestroy } from "@angular/core";
import { Subscription } from "rxjs";
import { Ingredient } from "src/app/models/ingredient.model";
import { Store } from '@ngrx/store';

import { AppState, ShoppingListState } from "../store/shoppping-list.reducer";
import { StartEditAction } from "../store/shopping-list.actions";

@Component({
  selector: 'app-shopping-list',
  templateUrl: 'shopping-list.component.html',
  styleUrls: [ 'shopping-list.component.css']
})
export class ShoppingListComponent implements OnInit, OnDestroy {

  myIngredients : Ingredient[] = [];
  myStoreSub! : Subscription;


  constructor(
    private store : Store<AppState>
  ) {}

  ngOnInit(): void {
    this.myStoreSub = this.store.select('shoppingList').subscribe(
      (shoppingListStore : ShoppingListState) => {
        this.myIngredients = shoppingListStore.ingredients;
      }
    );
  }


  ngOnDestroy(): void {
    this.myStoreSub.unsubscribe();
  }

  onIngredientSelected(i : number) {
    // when an ingredient is selected, send an event so the shopping-list-edit component
    // knows what ingredient is selected and displays it in the form
    this.store.dispatch(new StartEditAction(i))
  }

}
