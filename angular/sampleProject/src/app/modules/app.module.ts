// module imports
import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { ReactiveFormsModule } from '@angular/forms';
import { HttpClientModule, HTTP_INTERCEPTORS } from '@angular/common/http';
import { AppRoutingModule } from './app-routing.module';
import { SharedModule } from './shared.module';
import { RecipeModule } from './recipe.module';
import { ShoppingModule } from './shopping.module';

// component imports
import { AppComponent } from '../app.component';
import { HeaderComponent } from '../header/header.component';
import { NotFoundComponent } from '../not-found/not-found.component';
import { AuthComponent } from '../auth/auth.component';

// interceptor imports
import { AuthInterceptor } from '../services/auth.interceptor';


@NgModule({
  declarations: [
    AppComponent,
    HeaderComponent,
    NotFoundComponent,
    AuthComponent
  ],
  imports: [
    BrowserModule,
    SharedModule,
    ReactiveFormsModule,
    HttpClientModule,
    RecipeModule,
    ShoppingModule,
    AppRoutingModule  // need to be imported after all feature modules including routes, since it contains the wildcard route
  ],
  providers: [{
    provide:  HTTP_INTERCEPTORS,    // constant token to tell Angular it is an interceptor
    useClass: AuthInterceptor,
    multi:    true                  // to not overwrite other interceptors if any
  }],
  bootstrap: [AppComponent]
})
export class AppModule { }