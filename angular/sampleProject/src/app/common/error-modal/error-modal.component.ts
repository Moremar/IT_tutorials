import { Component, EventEmitter, Input, OnInit, Output } from '@angular/core';

@Component({
  selector: 'app-error-modal',
  templateUrl: './error-modal.component.html',
  styleUrls: ['./error-modal.component.css']
})
export class ErrorModalComponent implements OnInit {

  @Input() public message : string;

  // signals to the parent component that the modal was closed
  @Output() modalClosed = new EventEmitter<void>();

  constructor() { }

  ngOnInit(): void {
  }


  onClose() {
    this.modalClosed.emit();
  }

}
