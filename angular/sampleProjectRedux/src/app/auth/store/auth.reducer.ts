import { User } from "src/app/models/user.model"
import { AuthAction, LOGIN, LoginAction, LOGOUT } from "./auth.actions";

/**
 * Reducer function for the authentication section of the store
 */

export interface AuthState {
  user: User | null
};

const initialState : AuthState = {
  user: null
};

export function authReducer(state = initialState, action : AuthAction) : AuthState {
  switch (action.type) {
    case LOGIN: {
      const realAction = <LoginAction>action;
      return {
        ...state,
        user: realAction.payload
      };
    }
    case LOGOUT : {
      return {
        ...state,
        user: null
      };
    }
    default: {
      return state;
    }
  }
}
