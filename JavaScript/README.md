# JavaScript features

- weakly-typed language : variables have a type, but a variable can change type dynamically
- object-oriented language
- versatile language : runs in the browser for frontend, or on the server with Node.js


## Variable Declaration
#### var 

Variables declared with `var` are globally-scoped or function scoped.  
They can be re-declared without error :
```commandline
var a = 1;
var a = 2;
```

They are hoisted to the top of their scope :  no matter where they are declared, JS treats them as if they were declared at the top of their scope and set to `undefined`, so they can be referenced before they are declared :
```commandline
console.log(a);
var a = 1;
```

#### let

`let` should be used instead of `var` to declare non-constant JS variables.  
Variables declared with `let` are block-scoped, and cannot be re-declared in the same scope.  
They can be re-declared in a more nested scope, the inner variable then shadows the outer one.
```commandline
let a = 1;
if (true) {
    let a = 3;
}
```
They are also hoisted to the top of the block, but are not initialized to `undefined`, so referencing them before their declaration throws a `ReferenceError`.

#### const

Variables declared with `const` cannot be re-declared nor re-assigned.  
They are also block-scoped and not initialized to `undefined`.  
If an object or array is `const`, it cannot be re-assigned but its properties or elements can be changed :
```commandline
const obj = { a: 1, b: 2 };
obj.a = 3;
```

## Arrow And Anonymous functions

Arrow functions are a shorter form for anonymous functions.  

```commandline
// Arrow functions (lambdas)
const f1 = (a, b) => { return a + b; };
const f2 = (a, b) => a + b;

// Anonymous Functions
const f1 = function (a, b) { return a + b; };
```

The main difference is that anonymous functions have the `this` pointer set to the scope where they are defined, while arrow functions do not have their own `this` pointer, they inherit it from the parent scope.

```
const obj1 = { a: 1, f: () => console.log(this.a) };
obj1.f();  // undefined (look for "a" in the global scope)

const obj2 = { a: 1, f: function () { console.log(this.a); } };
obj2.f();  // 1
```

## array.map()

Used to apply a function to all elements of an array and return the resulting array :

```commandline
let arr = [1, 2, 3, 4];
let squares = arr.map(x => x * x);
```

## Spread operator

Use to copy an existing object or array and add some values to it :

```commandline
let arr1 = [ 1, 2, 3, 4 ];
let arr2 = [ ...arr, 5, 6 ];

let obj1 = { a: 1, b: 2 };
let obj2 = { ...obj1, c: 3 };
```

## Object Destructuring

Used to extract some properties from an object or array into variables or function parameters :

```commandline
let person = { name: 'Bob', age: 12 };
let hobbies = [ 'Cooking', 'Sport'];

// object destructuring into variables
let { name, age } = person;

// array destructuring
let [hobby1, hobby2] = hobbies;

// object destructuring into function parameters
function f({name, age}) {
    return name + ' is ' + age + ' years old.';
}
let message = f(person);
```

## Template Literals

We can create template string literals by using back-ticks instead of quotes.  
This lets us evaluate expressions and insert it into the string.
```commandline
let name = 'Tom';
let age = 12;
let message = `${name} is ${age} years old.`;
```