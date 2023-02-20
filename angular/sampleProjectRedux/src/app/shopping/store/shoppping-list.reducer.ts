import { Ingredient } from "../../models/ingredient.model";
import { ADD_INGREDIENT, ADD_INGREDIENTS, UPDATE_INGREDIENT, DELETE_INGREDIENT,
         START_EDIT, STOP_EDIT } from './shopping-list.actions';
import { ShoppingListAction, AddIngredientAction, AddIngredientsAction,
         UpdateIngredientAction, DeleteIngredientAction, StartEditAction } from './shopping-list.actions';

/**
 * Reducer function applying the required change to the state for each existing
 * action in the shopping list section
 */


export interface ShoppingListState {
  ingredients : Ingredient[],
  editedIngredient: Ingredient | null,
  editedIngredientIndex: number
};

const initialState : ShoppingListState = {
  ingredients : [
    new Ingredient("Chicken", 2),
    new Ingredient("Tomato", 10)
  ],
  editedIngredient: null,
  editedIngredientIndex: -1
};

export function shoppingListReducer(state = initialState, action : ShoppingListAction) : ShoppingListState {
  switch (action.type) {
    case ADD_INGREDIENT : {
      const realAction = <AddIngredientAction>action;
      return {
        ...state,     // spread operator to copy all properties of the previous state
        ingredients: [
          ...state.ingredients,
          realAction.payload
        ]
      };
    }
    case ADD_INGREDIENTS : {
      const realAction = <AddIngredientsAction>action;
      return {
        ...state,     // spread operator to copy all properties of the previous state
        ingredients: [
          ...state.ingredients,
          ...realAction.payload
        ]
      };
    }
    case UPDATE_INGREDIENT : {
      const realAction = <UpdateIngredientAction>action;
      let nextIngredients = [...state.ingredients];
      nextIngredients[state.editedIngredientIndex] = realAction.payload;
      return {
        ...state,
        ingredients: nextIngredients,
        editedIngredient: null,
        editedIngredientIndex: -1
      };
    }
    case DELETE_INGREDIENT : {
      const realAction = <DeleteIngredientAction>action;
      let nextIngredients = [...state.ingredients];
      nextIngredients.splice(state.editedIngredientIndex, 1);
      return {
        ...state,
        ingredients: nextIngredients,
        editedIngredient: null,
        editedIngredientIndex: -1
      };
    }
    case START_EDIT : {
      const realAction = <StartEditAction>action;
      const editedIngredientOriginal = state.ingredients[realAction.payload!];
      return {
        ...state,
        editedIngredient: new Ingredient(editedIngredientOriginal.name, editedIngredientOriginal.amount),
        editedIngredientIndex: realAction.payload
      };
    }
    case STOP_EDIT : {
      return {
        ...state,
        editedIngredient: null,
        editedIngredientIndex: -1
      };
    }
    default: {
      return state;
    }
  }
}
