export class Ingredient {

  /**
   * adding the "public" in front of the field names is a shortcut that automatically
   * creates the member variables as public and assign them in the constructor.
   *
   * Equivalent to :
   *
   * public name : string;
   * public amount : number;
   *
   * constructor(name: string, amount: number) {
   *     this.name = name;
   *     this.amount = amount;
   * }
   *
   */

  constructor(public name: string, public amount: number) {}
}
