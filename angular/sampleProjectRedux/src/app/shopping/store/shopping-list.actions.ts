import { Action } from "@ngrx/store";
import { Ingredient } from "src/app/models/ingredient.model";

/**
 * All Redux actions that can be sent to the store for the shopping list section
 * Each action must implement "Action", and therefore define a "type" member variable.
 * They can optionally take a payload that the reducer can use.
 */

// use a constant for each action name to help with Intellisense
export const ADD_INGREDIENT    = 'ADD_INGREDIENT';
export const ADD_INGREDIENTS   = 'ADD_INGREDIENTS';
export const UPDATE_INGREDIENT = 'UPDATE_INGREDIENT';
export const DELETE_INGREDIENT = 'DELETE_INGREDIENT';
export const START_EDIT        = 'START_EDIT';
export const STOP_EDIT         = 'STOP_EDIT';

export class AddIngredientAction implements Action {
  readonly type: string = ADD_INGREDIENT;
  constructor(public payload : Ingredient) {}
}

export class AddIngredientsAction implements Action {
  readonly type: string = ADD_INGREDIENTS;
  constructor(public payload : Ingredient[]) {}
}

export class UpdateIngredientAction implements Action {
  readonly type: string = UPDATE_INGREDIENT;
  constructor(public payload : Ingredient) {}}

export class DeleteIngredientAction implements Action {
  readonly type: string = DELETE_INGREDIENT;
  constructor() {}
}

export class StartEditAction implements Action {
  readonly type: string = START_EDIT;
  constructor(public payload : number) {}
}

export class StopEditAction implements Action {
  readonly type: string = STOP_EDIT;
  constructor() {}
}

// convenience union type for all shopping list actions
export type ShoppingListAction = AddIngredientAction
                               | AddIngredientsAction
                               | UpdateIngredientAction
                               | DeleteIngredientAction
                               | StartEditAction
                               | StopEditAction;
