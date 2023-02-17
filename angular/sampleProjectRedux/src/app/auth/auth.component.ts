import { Component, OnInit, ViewChild } from '@angular/core';
import { NgForm } from '@angular/forms';
import { Router } from '@angular/router';
import { Observable } from 'rxjs';
import { ErrorModalComponent } from '../common/error-modal/error-modal.component';
import { PlaceholderDirective } from '../directives/placeholder.directive';
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
  myErrorMessage : string | null = null;

  // get a reference on the template where we want to insert the modal
  @ViewChild(PlaceholderDirective) modalHost! : PlaceholderDirective;


  /* Constructor and life cycle hooks */

  constructor(
    private authService : AuthService,
    private router : Router
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
        this.showErrorModal();
      }
    );
  }


  /**
   * This method shows how to create programmatically a component and display it on the screen.
   *
   * Note that it is not the best way to do it in this example, it would have been much simpler to use *ngIf :
   *  <app-error-modal *ngIf="myErrorMessage" [message]="myErrorMessage" (modalClosed)="onCloseModal()"></app-error-modal>
   */
  showErrorModal() {
    // find where to insert the component
    const viewContainerRef = this.modalHost.viewContainerRef;
    viewContainerRef.clear();
    // create the component
    const modalRef = viewContainerRef.createComponent(ErrorModalComponent);
    // handle its Input (error message) and Output (close event)
    modalRef.instance.message = this.myErrorMessage || '';
    let subscription = modalRef.instance.modalClosed.subscribe(
      () => {
        subscription.unsubscribe();
        // clearing the placeholder container closes the modal
        this.myErrorMessage = null;
        viewContainerRef.clear();
      }
    );
  }

}
