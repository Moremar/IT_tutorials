import { Component, EventEmitter, Input, OnInit, Output } from '@angular/core';

@Component({
  selector: 'app-error-modal',
  templateUrl: './error-modal.component.html',
  styleUrls: ['./error-modal.component.css']
})
export class ErrorModalComponent implements OnInit {

  @Input() public message! : string;

  // signals to the parent component that the modal was closed
  @Output() modalClosed = new EventEmitter<void>();

  constructor() {}

  ngOnInit(): void {
    if (this.message == undefined) {
      throw new Error("The mandatory 'message' @Input is not defined");
    }
  }


  onClose() {
    this.modalClosed.emit();
  }

}
