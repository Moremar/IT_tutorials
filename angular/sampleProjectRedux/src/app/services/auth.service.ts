import { Injectable } from '@angular/core';
import { Router } from '@angular/router';
import { Observable, throwError } from 'rxjs';
import { catchError, tap } from 'rxjs/operators';
import { HttpClient, HttpParams, HttpErrorResponse } from '@angular/common/http';
import { Store } from '@ngrx/store';

import { environment } from '../../environments/environment';
import { Credentials } from '../models/credentials.model';
import { AuthResponse } from '../models/auth-response.model';
import { User } from '../models/user.model';
import { AppState } from '../store/app.reducer';
import { LoginAction, LogoutAction } from '../auth/store/auth.actions';


@Injectable({
  providedIn: 'root'
})
export class AuthService {

  readonly SIGNUP_URL : string = environment.firebase.signup_url;
  readonly LOGIN_URL : string = environment.firebase.login_url;
  readonly API_KEY : string = environment.firebase.api_key;
  readonly LOCAL_STORAGE_USER = 'loggedUser';


  private myTimeoutTimer : any;

  constructor(
    private http: HttpClient,
    private router: Router,
    private store: Store<AppState>
  ) {}


  signup(credentials: Credentials) : Observable<AuthResponse> {
    // return an Observable so the AuthComponent can update the template on loading/success/error
    return this.http
      .post<AuthResponse>(this.SIGNUP_URL, credentials, {params: new HttpParams().set('key', this.API_KEY)})
      .pipe(
        // HTTP errors can have multiple structure depending on the error (Firebase, network, ...)
        // This catchError operator transforms all errors into a single error message.
        catchError(this.handleAuthError),
        // on signup, capture the logged user
        tap(this.captureLoggedUser.bind(this))
      );
  }

  login(credentials: Credentials) : Observable<AuthResponse> {
    // return an Observable so the AuthComponent can update the template on loading/success/error
    return this.http
      .post<AuthResponse>(this.LOGIN_URL, credentials, {params: new HttpParams().set('key', this.API_KEY)})
      .pipe(
        // HTTP errors can have multiple structure depending on the error (Firebase, network, ...)
        // This catchError operator transforms all errors into a single error message.
        catchError(this.handleAuthError),
        // on login, capture the logged user
        tap(this.captureLoggedUser.bind(this))
      );
  }

  captureLoggedUser(responseData : AuthResponse) {
    const expiresIn = 1000 * Number(responseData.expiresIn);
    const expirationDate = new Date((new Date()).getTime() + expiresIn);
    const user = new User(responseData.email, responseData.localId, responseData.idToken, expirationDate);
    this.store.dispatch(new LoginAction(user));
    this.autoLogout(expiresIn);
    // stores the user to persistent storage so it is still accessible on refresh
    localStorage.setItem(this.LOCAL_STORAGE_USER, JSON.stringify(user));
  }

  // Common handling for signup and login to transform the HTTP error response into an error message
  handleAuthError(errorResponse: HttpErrorResponse) {
    let errorMessage = "An unknown error occured.";
    if (errorResponse.error && errorResponse.error.error && errorResponse.error.error.message) {
      switch (errorResponse.error.error.message) {
        case 'EMAIL_EXISTS':
          errorMessage = "This email is already in use.";
          break;
        case 'EMAIL_NOT_FOUND':
        case 'INVALID_PASSWORD':
          // same error for incorrect email or password to not give too much hint on the issue.
          errorMessage = "Invalid email or password.";
          break;
        case 'USER_DISABLED':
          errorMessage = "This user is no longer active.";
          break;
        default:
          errorMessage = "A Firebase REST API error occured :" + errorResponse.error.error.message;
          break;
      }
    }
    return throwError(() => errorMessage);
  }

  logout() {
    console.log('Logging out...');
    this.store.dispatch(new LogoutAction());
    localStorage.removeItem(this.LOCAL_STORAGE_USER);
    if (this.myTimeoutTimer) {
      clearTimeout(this.myTimeoutTimer);
    }
    this.router.navigate(['/auth']);
  }

  autoLogout(duration : number) {
    this.myTimeoutTimer = setTimeout(
      () => {
        console.log("Auth token expired.");
        this.logout();
      },
      duration
    );
  }

  autoLogin() {
    const userData = localStorage.getItem(this.LOCAL_STORAGE_USER);
    if (!userData) {
      return;
    }
    const userObj = JSON.parse(userData);
    if (!userObj) {
      // no user authentication info in the persistent storage
      return;
    }
    const userFromStorage = new User(userObj.email, userObj.userId, userObj._token, new Date(userObj._tokenExpirationDate));
    if (userFromStorage.token) {
      console.log('Auth token found, auto-login.');
      this.store.dispatch(new LoginAction(userFromStorage));
      let duration = (new Date(userObj._tokenExpirationDate)).getTime() - (new Date()).getTime();
      this.autoLogout(duration);
    }
  }

}
