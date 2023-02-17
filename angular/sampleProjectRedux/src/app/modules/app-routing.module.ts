import { NgModule } from '@angular/core';
import { Routes, RouterModule, PreloadAllModules } from '@angular/router';
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
  // routes which components are defined in this module
  { path: "auth", component: AuthComponent },
  // lazily loaded modules : instead of defining a component, we specify the TS module file to use and the service class name.
  // the import for this module is not at the top of this file so it does not get loaded at startup
  { path: "recipe", loadChildren: () => import('./recipe.module').then(m => m.RecipeModule) },
  { path: "**", component: NotFoundComponent }
];

@NgModule({
  // use Router.forRoot() in the main module routing
  // by default, the JS files for each lazy modules are loaded when needed, but we can specify
  // to pre-load them to improve performance
  imports: [RouterModule.forRoot(routes, {preloadingStrategy: PreloadAllModules})],
  exports: [RouterModule]
})
export class AppRoutingModule { }
