import { Action } from "@ngrx/store";
import { User } from "src/app/models/user.model";

/**
 * All Redux actions that can be sent to the store for the authentication section
 * Each action must implement "Action", and therefore define a "type" member variable.
 * They can optionally take a payload that the reducer can use.
 */

// use a constant for each action name to help with Intellisense
export const LOGIN  = '[auth] LOGIN';
export const LOGOUT = '[auth] LOGOUT';

export class LoginAction implements Action {
  readonly type: string = LOGIN;
  constructor(public payload : User) {}
}

export class LogoutAction implements Action {
  readonly type: string = LOGOUT;
  constructor() {}
}

export type AuthAction = LoginAction | LogoutAction;
