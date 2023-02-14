// module imports
import { AppRoutingModule } from './app-routing.module';
import { BrowserModule } from '@angular/platform-browser';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { HttpClientModule, HTTP_INTERCEPTORS } from '@angular/common/http';
import { NgModule } from '@angular/core';

// component imports
import { AppComponent } from './app.component';
import { ShoppingListComponent } from './shopping/shopping-list/shopping-list.component';
import { ShoppingListEditComponent } from './shopping/shopping-list-edit/shopping-list-edit.component';
import { HeaderComponent } from './header/header.component';
import { RecipeListComponent } from './recipe/recipe-list/recipe-list.component';
import { RecipeItemComponent } from './recipe/recipe-item/recipe-item.component';
import { RecipesComponent } from './recipe/recipes/recipes.component';
import { RecipeDetailsComponent } from './recipe/recipe-details/recipe-details.component';
import { NotFoundComponent } from './not-found/not-found.component';
import { RecipeEditComponent } from './recipe/recipe-edit/recipe-edit.component';
import { RecipeStartComponent } from './recipe/recipe-start/recipe-start.component';
import { AuthComponent } from './auth/auth.component';
import { LoadingSpinnerComponent } from './common/loading-spinner/loading-spinner.component';
import { ErrorModalComponent } from './common/error-modal/error-modal.component';
import { DropdownDirective } from './directives/dropdown.directive';
import { PlaceholderDirective } from './common/placeholder.directive';

// interceptor imports
import { AuthInterceptor } from './services/auth.interceptor';


@NgModule({
  declarations: [
    AppComponent,
    HeaderComponent,
    RecipeListComponent,
    RecipeItemComponent,
    RecipesComponent,
    RecipeDetailsComponent,
    RecipeEditComponent,
    ShoppingListComponent,
    ShoppingListEditComponent,
    NotFoundComponent,
    RecipeStartComponent,
    AuthComponent,
    LoadingSpinnerComponent,
    ErrorModalComponent,
    DropdownDirective,
    PlaceholderDirective,
  ],
  imports: [
    AppRoutingModule,
    BrowserModule,
    FormsModule,
    ReactiveFormsModule,
    HttpClientModule
  ],
  providers: [{
    provide:  HTTP_INTERCEPTORS,    // constant token to tell Angular it is an interceptor
    useClass: AuthInterceptor,
    multi:    true                  // to not overwrite other interceptors if any
  }],
  bootstrap: [AppComponent]
})
export class AppModule { }
