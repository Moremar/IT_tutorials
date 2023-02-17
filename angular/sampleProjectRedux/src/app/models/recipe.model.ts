import { Ingredient } from "./ingredient.model";

// export class Recipe {
//   public name: string;
//   public description: string;
//   public imageUrl: string;
//   public ingredients: Ingredient[];

//   constructor(name: string, description: string, imageUrl: string, ingredients: Ingredient[]) {
//     this.name = name;
//     this.description = description;
//     this.imageUrl = imageUrl;
//     this.ingredients = ingredients;
//   }
// }

// Simpler form to create a class with public fields
export class Recipe {

  constructor(
        public name: string,
        public description: string,
        public imageUrl: string,
        public ingredients: Ingredient[]) {}
}
