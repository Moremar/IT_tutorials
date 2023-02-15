import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';
import { AuthComponent } from '../auth/auth.component';
import { NotFoundComponent } from '../not-found/not-found.component';

/**
 * Module dedicated to the routes supported by the AppModule
 * It uses RouterModule.forRoot() to declare the routes.
 * If feature modules also define some routes, they will use Router.forChild() to declare them.
 *
 * Since it defines the wildcard route "**", it must be imported by the AppModule
 * after all other modules that include routes.
 */


const routes: Routes = [
  { path: "", redirectTo: "recipe", pathMatch: "full" },
  { path: "auth", component: AuthComponent },
  { path: "**", component: NotFoundComponent }
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],   // use Router.forRoot() in the main module routing
  exports: [RouterModule]
})
export class AppRoutingModule { }
