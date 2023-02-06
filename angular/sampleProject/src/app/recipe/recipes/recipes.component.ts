import { Component, OnInit } from '@angular/core';
import { Recipe } from 'src/app/models/recipe.model';

@Component({
  selector: 'app-recipes',
  templateUrl: './recipes.component.html',
  styleUrls: ['./recipes.component.css']
})
export class RecipesComponent implements OnInit {

  recipes : Recipe[] = [
    new Recipe("Roast Chicken", "Good raosted chicken extremely yummy like never before", "https://media.istockphoto.com/id/1317600394/photo/whole-roasted-chicken.jpg?s=612x612&w=0&k=20&c=2Z9NmYoQA2Wrys-EqvjYetVzbRdXdLho1Wbcqbl1PdQ="),
    new Recipe("French Fries", "Good french fries", "https://www.healthifyme.com/blog/wp-content/uploads/2022/07/shutterstock_1927479248-1.jpg")
  ];
  activeRecipe: Recipe = new Recipe("Hyppo", "This is a cute hyppo", "https://www.news.ucsb.edu/sites/default/files/slideshow_images/2019/iStock-1124637400.jpg");

  constructor() {}

  ngOnInit(): void {}

  onRecipeSelected(recipe : Recipe) {
    this.activeRecipe = recipe;
  }
}
