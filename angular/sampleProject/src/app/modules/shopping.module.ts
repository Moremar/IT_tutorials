import { NgModule } from '@angular/core';
import { ShoppingListComponent } from '../shopping/shopping-list/shopping-list.component';
import { ShoppingListEditComponent } from '../shopping/shopping-list-edit/shopping-list-edit.component';
import { RouterModule, Routes } from '@angular/router';
import { AuthGuard } from '../services/auth.guard';
import { SharedModule } from './shared.module';

/**
 * Feature module containing all the Shopping list related components
 * The module is small so we add the routes directly in it, not in a separate routing module
 */

const routes: Routes = [
  { path: "shoppinglist", component: ShoppingListComponent, canActivate: [AuthGuard] }
];

@NgModule({
  declarations: [
    ShoppingListComponent,
    ShoppingListEditComponent
  ],
  imports: [
    SharedModule,
    RouterModule.forChild(routes)
  ],
  // nothing to export since components are used only inside the module
  exports: []
})
export class ShoppingModule { }
