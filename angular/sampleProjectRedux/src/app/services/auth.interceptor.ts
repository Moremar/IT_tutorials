import { Injectable } from "@angular/core";
import { HttpInterceptor, HttpRequest, HttpHandler, HttpEvent } from '@angular/common/http';
import { Observable } from 'rxjs';
import { take, exhaustMap, map } from 'rxjs/operators';
import { Store } from "@ngrx/store";
import { AppState } from "../store/app.reducer";
import { AuthState } from "../auth/store/auth.reducer";
import { User } from "../models/user.model";

/**
 * Interceptor adding the authentication token to all outgoing HTTP requests
 * when the user is logged (and thus has an auth token)
 *
 * This is Injectable but should not be provided in "root", but added to
 * the "providers" property of the module (special way to provide interceptors)
 */


@Injectable()
export class AuthInterceptor implements HttpInterceptor {

  constructor(
    private store : Store<AppState>
  ) {}

  intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    return this.store.select('auth')
      .pipe(
        // take only the current state of the auth store, so we do not need to unsubscribe
        take(1),
        // extract the user from the auth store
        map(
          (authStore : AuthState) => {
            return authStore.user;
          }
        ),
        // replace the current Observable by another Observable
        exhaustMap(
          (user : User | null) => {
            if (user) {
              // when a logged user object is available, attach the auth token to the request
              const modifiedReq = req.clone({ params: req.params.set('auth', user.token || '') });
              // Pass the cloned request to the next handler.
              return next.handle(modifiedReq);
            } else {
              // no logged user available, just forward the request
              // this is the expected behavior for signup/login requests before the user is logged in
              return next.handle(req);
            }
          }
        )
      );
  }

}
