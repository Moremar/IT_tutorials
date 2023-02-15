// Modules
import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';
// Components
import { RecipeDetailsComponent } from '../recipe/recipe-details/recipe-details.component';
import { RecipeEditComponent } from '../recipe/recipe-edit/recipe-edit.component';
import { RecipeStartComponent } from '../recipe/recipe-start/recipe-start.component';
import { RecipesComponent } from '../recipe/recipes/recipes.component';
// Guards
import { AuthGuard } from '../services/auth.guard';
import { RecipesResolverGuard } from '../services/recipes-resolver.guard';


const routes: Routes = [
  { path: "recipe", component: RecipesComponent, canActivate: [AuthGuard], children: [
      { path: "", pathMatch: "full", component: RecipeStartComponent },
      { path: "new", component: RecipeEditComponent },
      { path: ":id", component: RecipeDetailsComponent, resolve: [RecipesResolverGuard] },
      { path: ":id/edit", component: RecipeEditComponent, resolve: [RecipesResolverGuard] }
  ]}
];

@NgModule({
  imports: [RouterModule.forChild(routes)],  // use Router.forChild() in feature module routing
  exports: [RouterModule]
})
export class RecipeRoutingModule { }
