import { Directive, ElementRef, HostListener, Renderer2 } from '@angular/core';

/**
 * This is an example of directive that can be attached to any component.
 * When the component is clicked, it will receive the class "open" set to it.
 * If it is clicked again, it will lose the class "open".
 *
 * This directive is currently not used (we are using Bootstrap for dropdowns)
 */

@Directive({
  selector: '[appDropdown]'
})
export class DropdownDirective {

  isOpen: boolean = false;

  @HostListener('click') onClick() {
    this.isOpen = !this.isOpen;
    if (this.isOpen) {
      // attach a class to open the dropdown
      this.renderer.addClass(this.elementRef.nativeElement, 'open');
    } else {
      // detach a class to class the dropdown
      this.renderer.removeClass(this.elementRef.nativeElement, 'open');
    }
  }

  constructor(
    private elementRef: ElementRef,
    private renderer: Renderer2
  ) {}

}
