// modules
import { NgModule } from '@angular/core';
import { ReactiveFormsModule } from '@angular/forms';
import { RouterModule } from '@angular/router';
import { SharedModule } from './shared.module';
import { RecipeRoutingModule } from './recipe-routing.module';
// components
import { RecipeListComponent } from '../recipe/recipe-list/recipe-list.component';
import { RecipeItemComponent } from '../recipe/recipe-item/recipe-item.component';
import { RecipesComponent } from '../recipe/recipes/recipes.component';
import { RecipeDetailsComponent } from '../recipe/recipe-details/recipe-details.component';
import { RecipeEditComponent } from '../recipe/recipe-edit/recipe-edit.component';
import { RecipeStartComponent } from '../recipe/recipe-start/recipe-start.component';

/**
 * Feature module containing all the Recipe related components.
 * Its routing is handled by a separate module (RecipeRoutingModule)
 */


@NgModule({
  declarations: [
    RecipeListComponent,
    RecipeItemComponent,
    RecipesComponent,
    RecipeDetailsComponent,
    RecipeEditComponent,
    RecipeStartComponent
  ],
  imports: [
    SharedModule,
    RouterModule,
    ReactiveFormsModule,
    RecipeRoutingModule
  ],
  exports: []
})
export class RecipeModule { }
