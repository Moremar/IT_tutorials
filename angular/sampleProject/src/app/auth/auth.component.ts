import { Component, OnInit } from '@angular/core';
import { NgForm } from '@angular/forms';
import { Router } from '@angular/router';
import { Observable } from 'rxjs';
import { AuthResponse } from '../models/auth-response.model';
import { Credentials } from '../models/credentials.model';
import { AuthService } from '../services/auth.service';


@Component({
  selector: 'app-auth',
  templateUrl: './auth.component.html',
  styleUrls: ['./auth.component.css']
})
export class AuthComponent implements OnInit {

  /* Member variables */

  myIsLoading : boolean = false;
  myErrorMessage : string = null;


  /* Constructor and life cycle hooks */

  constructor(
    private authService : AuthService,
    public router : Router
  ) {}

  ngOnInit(): void {}


  /* Methods */

  onSignup(form : NgForm) {
    console.log("Signing up...");
    const credentials = new Credentials(form.value.userEmail, form.value.userPassword);
    return this.authenticate(this.authService.signup(credentials));
  }

  onLogin(form : NgForm) {
    console.log("Logging in...");
    const credentials = new Credentials(form.value.userEmail, form.value.userPassword);
    return this.authenticate(this.authService.login(credentials));

  }

  authenticate(authObservable : Observable<AuthResponse>) {
    // common handling for signup and login
    this.myIsLoading = true;
    authObservable.subscribe(
      (result: AuthResponse) => {
        this.myIsLoading = false;
        this.router.navigate(['/recipe']);
      },
      (errorMessage : string) => {
        this.myErrorMessage = errorMessage;
        this.myIsLoading = false;
      }
    );
  }

}
