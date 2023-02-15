import { Directive, ViewContainerRef } from '@angular/core';

/**
 * Directive used only to mark a tag that is used as a template to generate
 * dynamically a component at a given position
 */


@Directive({
  selector: '[appPlaceholder]'
})
export class PlaceholderDirective {

  // the container reference must be public because we will access it from other
  // component to specify where to insert a dynamically created component
  constructor(public viewContainerRef: ViewContainerRef) {}

}
