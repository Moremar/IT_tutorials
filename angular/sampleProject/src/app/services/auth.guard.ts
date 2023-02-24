import { Injectable } from '@angular/core';
import { CanActivate, ActivatedRouteSnapshot, RouterStateSnapshot, Router, UrlTree } from '@angular/router';
import { Observable } from 'rxjs';
import { map, take } from 'rxjs/operators';
import { User } from '../models/user.model';
import { AuthService } from './auth.service';

/**
 * Authentication guard redirecting to the auth page when trying to access routes
 * that require to be logged in (recipes and shoppinglist)
 */


@Injectable({
  providedIn: 'root'
})
export class AuthGuard implements CanActivate {

  constructor(
    private authService: AuthService,
    private router: Router
  ) {}

  canActivate(
    route: ActivatedRouteSnapshot,
        state: RouterStateSnapshot): boolean | UrlTree | Observable<boolean | UrlTree> | Promise<boolean | UrlTree> {
    return this.authService.loggedUser
      .pipe(
        // only care about 1 value of the logged user
        take(1),
        // return true only if the user is authenticated
        map(
          (loggedUser: User | null) => {
            // user is logged in, the route can be activated
            if (loggedUser && loggedUser.token !== null) {
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
