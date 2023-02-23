import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ErrorModalComponent } from '../common/error-modal/error-modal.component';
import { LoadingSpinnerComponent } from '../common/loading-spinner/loading-spinner.component';
import { ComponentForTestComponent } from '../component-for-test/component-for-test.component';

import { PlaceholderDirective } from '../directives/placeholder.directive';
import { DropdownDirective } from '../directives/dropdown.directive';
import { FormsModule } from '@angular/forms';

/**
 * Shared module that declares and exports components and modules used
 * across multiple modules
 */


@NgModule({
  declarations: [
    ErrorModalComponent,
    LoadingSpinnerComponent,
    PlaceholderDirective,
    DropdownDirective,
    ComponentForTestComponent
  ],
  imports: [
    // modules that we want all other modules to import
    CommonModule,
    FormsModule
  ],
  // export everything it declares and imports
  exports: [
    CommonModule,
    FormsModule,
    ErrorModalComponent,
    LoadingSpinnerComponent,
    PlaceholderDirective,
    DropdownDirective,
    ComponentForTestComponent
  ]
})
export class SharedModule { }
