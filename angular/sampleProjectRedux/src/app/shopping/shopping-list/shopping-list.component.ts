import { Component, OnInit, OnDestroy } from "@angular/core";
import { Subscription } from "rxjs";
import { Ingredient } from "src/app/models/ingredient.model";
import { ShoppingListService } from "src/app/services/shopping-list.service";


@Component({
  selector: 'app-shopping-list',
  templateUrl: 'shopping-list.component.html',
  styleUrls: [ 'shopping-list.component.css']
})
export class ShoppingListComponent implements OnInit, OnDestroy {

  myIngredients : Ingredient[] = [];
  myIngredientsSub! : Subscription;


  constructor(private shoppingListService : ShoppingListService) {}

  ngOnInit(): void {
    this.myIngredients = this.shoppingListService.getIngredients();
    this.myIngredientsSub = this.shoppingListService.ingredientsChanged.subscribe(
      (ingredients : Ingredient[]) => {
        this.myIngredients = ingredients;
      }
    );
  }

  ngOnDestroy(): void {
    this.myIngredientsSub.unsubscribe();
  }

  onIngredientSelected(i : number) {
    // when an ingredient is selected, send an event so the shopping-list-edit component
    // knows what ingredient is selected and displays it in the form
    this.shoppingListService.startedEditing.next(i);
  }

}
