import { Component, OnInit, OnDestroy } from '@angular/core';
import { Subscription } from 'rxjs';
import { User } from '../models/user.model';
import { AuthService } from '../services/auth.service';
import { DataStorageService } from '../services/data-storage.service';


@Component({
  selector: 'app-header',
  templateUrl: './header.component.html',
  styleUrls: ['./header.component.css']
})
export class HeaderComponent implements OnInit, OnDestroy {

  /* Member variables */

  public myIsLogged = false;
  private myLoggedUserSub!: Subscription;


  /* Constructor and life cycle hooks */

  constructor(
    private dataStorageService: DataStorageService,
    private authService: AuthService
  ) {}

  ngOnInit(): void {
    this.myLoggedUserSub = this.authService.loggedUser.subscribe(
      (loggedUser: User | null) => {
        this.myIsLogged = loggedUser !== null && loggedUser.token !== null;
      }
    );
  }

  ngOnDestroy(): void {
    this.myLoggedUserSub.unsubscribe();
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
