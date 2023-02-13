import { Injectable } from "@angular/core";
import { HttpInterceptor, HttpRequest, HttpHandler, HttpEvent } from '@angular/common/http';
import { Observable } from 'rxjs';
import { take, exhaustMap } from 'rxjs/operators';
import { AuthService } from "./auth.service";
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

  constructor(private authService : AuthService) {}

  intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    return this.authService.loggedUser
      .pipe(
        // take only the 1st element of the loggedUser BehaviorSubject, so we do not need to unsubscribe
        take(1),
        // replace the current Observable by another Observable
        exhaustMap(
          (loggedUser : User) => {
            if (loggedUser) {
              // when a logged user object is available, attach the auth token to the request
              const modifiedReq = req.clone({ params: req.params.set('auth', loggedUser.token) });
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
