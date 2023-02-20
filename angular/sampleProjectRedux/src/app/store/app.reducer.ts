import { ActionReducerMap } from "@ngrx/store";
import { authReducer, AuthState } from "../auth/store/auth.reducer";
import { shoppingListReducer, ShoppingListState } from "../shopping/store/shoppping-list.reducer";

/**
 * Define a top-level reducer map that groups all reducers of the app (one for each section)
 * This reducer map is used in app.module.ts when importing the StoreModule
 *
 * We also define here AppState, the top-level structure of our state.
 * It has a preperty for each section, with a section-specific state in each.
 */

export interface AppState {
  auth: AuthState,
  shoppingList: ShoppingListState
};

export const appReducer: ActionReducerMap<AppState> = {
  auth: authReducer,
  shoppingList: shoppingListReducer
};
