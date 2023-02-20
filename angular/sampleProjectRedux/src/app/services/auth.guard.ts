import { Injectable } from '@angular/core';
import { CanActivate, ActivatedRouteSnapshot, RouterStateSnapshot, Router, UrlTree } from '@angular/router';
import { Observable } from 'rxjs';
import { map, take } from 'rxjs/operators';
import { Store } from "@ngrx/store";
import { AppState } from '../store/app.reducer';
import { AuthState } from '../auth/store/auth.reducer';
import { User } from '../models/user.model';

/**
 * Authentication guard redirecting to the auth page when trying to access routes
 * that require to be logged in (recipes and shoppinglist)
 */


@Injectable({
  providedIn: 'root'
})
export class AuthGuard implements CanActivate {

  constructor(
    private router : Router,
    private store : Store<AppState>
  ) {}

  canActivate(
        route: ActivatedRouteSnapshot,
        state: RouterStateSnapshot): boolean | UrlTree | Observable<boolean | UrlTree> | Promise<boolean | UrlTree> {
      return this.store.select('auth')
      .pipe(
        // only care about 1 value of the logged user
        take(1),
        // get only the user from the auth store
        map(
          (authStore : AuthState) => {
            return authStore.user;
          }
        ),
        // return true only if the user is authenticated
        map(
          (user : User | null) => {
            // user is logged in, the route can be activated
            if (user && user.token !== null) {
              return true;
            }
            // user is not logged in, redirect to the auth page
            console.log('URL requires to be authenticated, redirect to auth page.');
            return this.router.createUrlTree(['/auth']);
          }
        )
      );
  }

}
