import { Component, EventEmitter, OnInit, Output } from '@angular/core';

@Component({
  selector: 'app-header',
  templateUrl: './header.component.html',
  styleUrls: ['./header.component.css']
})
export class HeaderComponent implements OnInit {

  @Output() pageSelected = new EventEmitter<string>();

  constructor() { }

  ngOnInit(): void { }

  selectPage(pageName : string) {
    this.pageSelected.emit(pageName);
  }

  onSelectRecipes() {
    this.selectPage("recipes");
  }

  onSelectShoppingList() {
    this.selectPage("shopping-list");
  }

  onSaveData() {
    alert("TODO : Save Data");
  }

  onLoadData() {
    alert("TODO : Load Data");
  }
}
