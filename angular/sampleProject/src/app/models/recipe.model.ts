
// export class Recipe {
//   public name: string;
//   public description: string;
//   public imageUrl: string;

//   constructor(name: string, description: string, imageUrl: string) {
//     this.name = name;
//     this.description = description;
//     this.imageUrl = imageUrl;
//   }
// }

// Simpler form to create a class with public fields
export class Recipe {

  constructor(
        public name: string,
        public description: string,
        public imageUrl: string) {}
}
