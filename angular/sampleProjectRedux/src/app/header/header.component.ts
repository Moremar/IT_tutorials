import { Component, OnInit, OnDestroy } from '@angular/core';
import { Subscription } from "rxjs";
import { map } from 'rxjs/operators'
import { Store } from "@ngrx/store";
import { AuthService } from '../services/auth.service';
import { DataStorageService } from '../services/data-storage.service';
import { AppState } from '../store/app.reducer';
import { AuthState } from '../auth/store/auth.reducer';
import { User } from '../models/user.model';


@Component({
  selector: 'app-header',
  templateUrl: './header.component.html',
  styleUrls: ['./header.component.css']
})
export class HeaderComponent implements OnInit, OnDestroy {

  /* Member variables */

  public myIsLogged : boolean = false;
  private myStoreSub! : Subscription;


  /* Constructor and life cycle hooks */

  constructor(
    private dataStorageService : DataStorageService,
    private authService : AuthService,
    private store : Store<AppState>
  ) {}

  ngOnInit(): void {
    this.myIsLogged = false;
    this.myStoreSub = this.store.select('auth')
    .pipe(
      map(
        (authStore : AuthState) => {
          return authStore.user
        }
      )
    )
    .subscribe(
      (loggedUser: User | null) => {
        this.myIsLogged = loggedUser !== null && loggedUser.token !== null;
      }
    );
  }

  ngOnDestroy(): void {
    this.myStoreSub.unsubscribe();
  }


  /* Methods */

  onSaveData() {
    this.dataStorageService.saveRecipesToBackend();
  }

  onLoadData() {
    // nothing to do with the result, but we need to subscribe for the HTTP request to be generated
    this.dataStorageService.loadRecipesFromBackend().subscribe();
  }

  onLogout() {
    this.authService.logout();
  }

}
