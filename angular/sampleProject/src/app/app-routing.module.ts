import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';
import { AuthComponent } from './auth/auth.component';
import { NotFoundComponent } from './not-found/not-found.component';
import { RecipeDetailsComponent } from './recipe/recipe-details/recipe-details.component';
import { RecipeEditComponent } from './recipe/recipe-edit/recipe-edit.component';
import { RecipeStartComponent } from './recipe/recipe-start/recipe-start.component';
import { RecipesComponent } from './recipe/recipes/recipes.component';
import { ShoppingListComponent } from './shopping/shopping-list/shopping-list.component';

import { AuthGuard } from './services/auth.guard';
import { RecipesResolverGuard } from './services/recipes-resolver.guard';


const routes: Routes = [
  { path: "", redirectTo: "recipe", pathMatch: "full" },
  { path: "auth", component: AuthComponent },
  { path: "recipe", component: RecipesComponent, canActivate: [AuthGuard], children: [
      { path: "", pathMatch: "full", component: RecipeStartComponent },
      { path: "new", component: RecipeEditComponent },
      { path: ":id", component: RecipeDetailsComponent, resolve: [RecipesResolverGuard] },
      { path: ":id/edit", component: RecipeEditComponent, resolve: [RecipesResolverGuard] }
  ]},
  { path: "shoppinglist", component: ShoppingListComponent, canActivate: [AuthGuard] },
  { path: "**", component: NotFoundComponent }
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
