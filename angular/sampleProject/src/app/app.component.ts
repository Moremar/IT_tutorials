import { Component } from '@angular/core';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent {
  title = 'sampleProject';

  pageDisplayed : string = "recipes";

  onPageSelected(pageName: string) {
    console.log("selected " + pageName);
    this.pageDisplayed = pageName;
  }

  shouldDisplayRecipes() {
    return this.pageDisplayed === "recipes";
  }

  shouldDisplayShoppingList() {
    return this.pageDisplayed === "shopping-list";
  }
}
