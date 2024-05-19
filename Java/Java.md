# Java Tutorial

## Installation

Install the latest LTS JDK from [https://www.oracle.com/java/technologies/](https://www.oracle.com/java/technologies/) 

Install Intellij IDEA to edit Java code.

## Java Components

### JRE (Java Runtime Environment)

The JRE is a set of software and tools that enables Java applications to run on a system.  
It contains a JVM (Java Virtual Machine) responsible to execute Java bytecode.  
It does not include any development tools (compiler, debugger...).  

### JDK (Java Development Kit)

The JDK provides all components needed to develop, compile, debug and run Java software.  
It includes the JRE, as well as development tools like the `javac` Java compiler and the `jdb` debugger.  

### javac (Java Compiler)

The `javac` compiler turns Java source code into platform-independent Java bytecode.  
Unlike C or C++, the compiled bytecode is not directly executable by the target system.  
It is an intermediate format executed by the JVM that must be installed on the system running the Java application.

### JVM (Java Virtual Machine)

The JVM is a critical component of the Java platform that executes Java bytecode.  
It provides a runtime for the same Java application to run on various hardware and OS.  
It is the main component behind the "Write Once, Run Anywhere" Java philosophy.  
The JVM manages memory allocation and garbage collection.

### JShell

The JShell is an interactive tool introduced in JDK 9 for learning the Java and prototyping Java code.  
It is a Read-Evaluate-Print Loop tool (REPL) started from the command-line with the `jshell` command.  
It evaluates declarations, statements, and expressions as they are entered and immediately shows the results.  

## Basics

### Basic program

```java
// specify the package of the class
package com.example;

// each Java file should define a class
public class ExampleMain {

    // a program needs an entry-point main() method to run
    // it takes a parameter of type String[] (array) or String... (elision) to store the program arguments
    public static void main(String[] args) {
        System.out.println("Running...");
    }
}
```

### Primitive types

Java supports 8 primitive data types that are not classes.  
Each primitive data type has a corresponding wrapper class that provides constants and methods.
- `byte` : 1-byte signed integer (-128 to 127), wrapper class `Byte`
- `short` : 2-bytes signed integer (-32k to 32k), wrapper class `Short`
- `int` : 4-bytes signed integer (-2.1B billion to 2.1 billion), wrapper class `Integer`, preferred type for integers
- `long` : 8-bytes signed integer (-2^63 to 2^63 - 1), wrapper class `Long`
- `float` : 4-bytes decimal number, wrapper class `Float`
- `double` : 8-bytes decimal number, wrapper class `Long`, preferred type for floating point numbers
- `char` : 2-bytes single character, wrapper class `Character`, can be initialized from the unicode number or the decimal value
- `boolean` : true or false, wrapper class `Boolean` 

Both `float` and `double` types are not exact, due to the way they store numbers with a certain precision.  
For exact decimal calculations, we should use the `BigDecimal` class instead.

```java
// print a message
System.out.println("integer range : " + Integer.MIN_VALUE + " to " + Integer.MAX_VALUE + "(" + Integer.SIZE + " bits)");

// variables
int myInt = 12;
myInt += 10;                        // addition compound operator
myInt++;                            // increment operator
long myLong = 65_000_000_000L;      // l or L suffix for long litteral
float myFloat= 12.5f;               // f or F suffix for double litteral (by default decimals use double in Java)
char myUnicode = '\u0044';          // 'D' character by unicode number

// cast
byte myByte = Byte.MAX_VALUE;
myByte = (byte) (myByte / 2);      // cast required, otherwise Java considers the expression as an int
```


### Java built-in classes


#### Primitive type wrappers

Each of the primitive type has a corresponding Java built-in wrapper class exposing constants and methods.  
The wrapper classes are : `Byte`, `Short`, `Integer`, `Long`, `Float`, `Double`, `Character`, `Boolean`


#### String

The `String` class represents an immutable sequence of characters, that can include unicode characters.

```java
String myStr = "This cost 10\u0024 !";      // \u0024 is the unicode representation of '$'
myStr = new String("Hi");                   // instanciate string by constructor with the "new" keyword

int a = Integer.parseInt("1234");           // parse a string to an int
double a = Double.parseDouble("1.234");     // parse a string to a double

// description methods
myStr.length();
myStr.charAt(0);
myStr.indexOf('a');
myStr.lastIndexOf('a');
myStr.isEmpty();
myStr.isBlank();                            // since JDK 11, true if the string contains only whitespaces

// comparison methods
myStr.equals("aaa");                        // test equality (case-sensitive)
myStr.equalsIgnoreCase("aaa");              // test equality (case-insensitive)
myStr.contains("aaa");
myStr.endsWith("aaa");
myStr.startsWith("aaa");

// modification methods
myStr.trim();                               // remove leading and trailing whitespaces (space, tab, newline)
myStr.strip();                              // since Java 11, similar to trim() but remove more unicode whitespaces
myStr.stripLeading();
myStr.stripTrailing();
myStr.toLowerCase();
myStr.toUpperCase();
myStr.concat("AAA");
myStr.split("-");
String.join(" / ", "A", "B", "C");          //  A / B / C
myStr.repeat(3);                            // since Java 11
myStr.replace("aa", "bb");                  // replace all occurences of a string by another
myStr.replaceAll("[aeiou]", "X");           // replace all occurences of a regex by a string
myStr.replaceFirst("[aeiou]" "X");          // replace first occurence of a regex by a string
myStr.substring(2, 4);                      // return substring from index 2 (inclusive) to index 4 (exclusive)
```

We can use the `StringBuilder` class for a mutable string object.  
Unlike the `String` variants, all modifications on StringBuilder (concatenation, upper case...) are performed in-place.  
StringBuilder methods return a self-reference, to allow method chaining.

```java
StringBuilder builder = new StringBuilder("Hello");
builder.append(" World")              // Hello World
       .deleteCharAt(4)                 // Hell World
       .insert(4, " of a")              // Hell of a World
       .replace(10, 15, "Day")          // Hell of a Day
       .reverse()                       // yaD a fo lleH
       .setLength(3);                   // yaD

System.out.println(builder);            // call the toString() method that creates a String
```

Since JDK 15, Java introduced `text blocks` with triple double-quotes for formatted multi-line strings :
```java
String blockStr = """
    To buy :
      \u2022 Tomatoes 
      \u2022 Potatoes """;
```

Strings can also be formatted to replace placeholders with values :
```java
int age = 13;
double grade = 12.5;

// concatenation with the + operator (supported for integer and double)
String myStr = "Age: " + age + "  Grade: " + grade;

// formatting
String formatted1 = String.format("Age: %d  Grade: %.2f", age, grade);   // Age: 13  Grade: 12.50
String formatted2 = "Age: %d  Grade: %.2f".formatted(age, grade);        // Age: 13  Grade: 12.50
```

#### Arrays

Arrays are instances of a built-in class that inherits from Object and has a single field called `length`.

```java
int[] myArray;                           // array declaration 
int myArray[];                           // alternative syntax (to avoid)
int[] myArray = new int[4];              // array declaration and instanciation (size required and fixed)
int[] myArray = new int[]{1, 2, 3, 4};   // array declaration, instanciation and initialization
int[] myArray = {1, 2, 3, 4};            // alternative syntax, only allowed in delaration
myArray = new int[]{1, 2, 3, 4};         // existing array assignment
myArray = { 1, 2, 3, 4 }; // NOT VALID!

myArray[1] = 100;
myArray.length;                          // array length
myArray.getClass().getSimpleName();      // int[]

// for loop on an array 
for (int item : myArray) {
  System.out.println(item);
}
```

The `java.util.Arrays` class offers some useful methods to manipulate arrays.  
Methods like search or sort algorithms are overloaded for all basic types and for Object.

```java
myArray.toString();                        // [I@27974e9a   (array of int at a specific address)
Arrays.toString(myArray);                  // [1, 2, 3]     (call toString() on each item)
Arrays.deepToString(myArray);              // [1, 2, 3]     (call Arrays.toString() on each item)

Arrays.fill(myArray, 5);                   // set all items of the array to 5 in-place

Arrays.sort(myArray);                      // sort the array in-place in ascending order

Arrays.binarySearch(myArray, 2);           // index of the item in a SORTED array by binary search
                                           // if not found, return -1 * insertion index (index where the item would be)

Arrays.copyOf(myArray, 15);                // shallow copy of the array (truncate or pad with 0 to reach target size 15)

Arrays.equals(myArray, myArray2);           // test content equality between 2 arrays
```

We can declare multi-dimensional arrays like matrices using nested arrays :
```java
// 2D square matrix
int[][] myMatrix = { {1, 2, 3}, {4, 5, 6}, {7, 8, 9} };

// 2D array with lines of different size
int[][] myMatrix = { {1}, {2, 3}, {4, 5, 6} };

// define a 2D square matrix without initializing it
int[][] myMatrix = new int[3][3];

// define a 2D array of int with 3 lines of variable length
int[][] myMatrix = new int[3][];
```

#### Random

The `java.util.Random` class exposes a pseudo-random numbers generator.

```java
Random random = new Random();
random.nextInt();                 // pseudo-random integer in [0, MAX_INT] (max_INT = 2^32 = 4.2M)
random.nextInt(10);               // pseudo-random integer in [0, 9]
random.nextDouble();              // pseudo-random double in [0.0, 1.0[
random.nextDouble(10.0);          // pseudo-random double in [0.0, 10.0[
```

#### BigDecimal

BigDecimal is used for floating point objects that need exact precision (float and double truncate the result).


### Type inference


Local variable inference war introduced with Java 10 with the `var` keyword to improve readability.  
It infers the type at compile-time, and is allowed only when the compiler can deduce the type from the assigned value.
```java
var movie = new Movie("Interstellar");
```

To check the runtime-type of an object we can use the `getClass()` method.  
We can also test if an object is an instance of a class using the `instanceof` operator :
```java
boolean isPerson1 = myObj.getClass().getSimpleName().equals("Person");    // true if class is Person
boolean isPerson2 = myObj instanceof Person;                              // true if class is Person or derived

// syntax added in Java 16 to automatically cast an object with instanceof
if (myObj instanceof Person myPerson) {
    myPerson.doSomething();
}
```

## Control Flow

### if / else

```java
if (myAge > 18 && isMember) {
   System.out.println("You are an adult member");
} else if (!isMember) {
   System.out.println("You are an adult non-member");
} else {
   System.out.println("You are a child");
}

// turnary operator
String status = myAge > 18 ? "adult" : "child"; 
```

### switch / case

```java
// old syntax
int myVal = 1;
switch (myVal) {
  case 0:
    System.out.println("Val is 0");
    break;
  case 1:  // fall-through
  case 2:
    System.out.println("Val is 1 or 2");
    break;
  default:
    System.out.println("Val is not 0 / 1 / 2");
}

// since java 9, we can use a modern syntax (no need for breaks since no fall-through)
switch (myVal) {
  case 0    -> System.out.println("Val is 0");
  case 1, 2 -> System.out.println("Val is 1 or 2");
  default   -> System.out.println("Val is not 0 / 1 / 2");
}

// since Java 12, we can use the modern switch syntax as the return value of a method or as an expression to assign a variable
// since Java 14, the "yield" keyword is added to a switch block to return a value
public static int getQuarter(int month) {
  return switch (month) {
    case 0, 1, 2   -> 1;
    case 3, 4, 5   -> 2;
    case 6, 7, 8   -> 3;
    case 9, 10, 11 -> 4;
    default        -> {
      System.out.println("invalid month: " + month);
      yield -1;                             // alternative using "yield", used when calculations are needed
    }
  }
}
```

### for loop

```java
for (int i = 0; i < 5; i++) {
  [ ... ]
}
```

### while / do...while loop

```java
// while loop
boolean stop = false;
while (!stop) {
  [ ... ]
}

// do...while loop (execute at least once)
boolean stop = true;
do {
  [ ... ]
} while (!stop);
```


## Exception Handling

```java
try {
    System.console().readLine("Your name: ");   // throw a NullPointerException when run in IntelliJ IDEA
} catch (NullPointerException e) {
    System.out.println("No console available.");
}
```


## User Input

- **Command line argument** : commonly used but does not allow an interactive application.


- **System.in** : provided by Java to read input from the console, it is not user-friendly and a lot of code builds above it to make it easier.


- **System.console** : Java solution to read a single line from the console.  
It does not work when run from IntelliJ IDEA that disables the console, the `System.console()` method returns `null`.
```java
String name = System.console().readLine("Your name: ");
```

- **Scanner** : common way to read input either from System.in or from a file, available in `java.util` library
```java
Scanner scanner = new Scanner(System.in);           // scanner reading from terminal
Scanner scanner = new Scanner(new File(myPath));    // scanner reading from a file

System.out.print("Your name: ");
String name = scanner.nextLine();
```


## OOP (Object-Oriented Programming)

### Classes

Classes in Java are organized into logical groups called **packages**, defined by the `package` statement.  
When its package is not specified, a class belongs to the default package.  
A common practice is to start the package name with `com.<COMPANY_NAME>`.  
The fully qualified name of a class must be unique (the class name must be unique within its package).

A top-level class can have 2 access modifiers :
- `public` to allow any class to access it
- no access modifier to limit access to classes in the same package

Instance fields and methods also have an access modifier :
- `public` to allow access to any class
- `protected` to allow access only to classes in the same package **or subclasses in any package**
- `private` to not allow access to any class
- no modifier (package-access) to allow access only to classes in the same package

Instance fields of primary types are defaulted to 0 / 0.0 / false when not initialized.  
Instance fields of class types are defaulted to null when not initialized.

An object is instantiated with the `new` keyword, it creates an instance and returns a reference to the object.  
If we assign this object to another variable, then both variables are references pointing to the same object in memory.

Methods take basic type parameters by value and class parameters by reference.  
This means that a method can modify all original class objects received as parameters.

```java
public class Person {

    // constructors
    public Person() {             // default constructor
        this("?", "?", false);    // constructor chaining, must be the 1st instruction in the constructor
    }
    
    public Person(String firstName, String lastName, boolean status) {
        this.firstName = firstName;
        this.lastName = lastName;
        this.status = status;
    }
    
    // instance fields
    private String firstName;
    private String lastName;
    private boolean single = true;         // default value
    
    // getters
    public String getFirstName() { return firstName; }
    public String getLastName()  { return lastName; }
    public boolean isStatus()    { return status; }

    // setters (allow parameter validation before assignment)
    public void setFirstName(String firstName) { this.firstName = firstName; }
    public void setLastName(String lastName)   { this.lastName = lastName; }
    public void setStatus(boolean status)      { this.status = status; }
            
    // instance method
    public void describe() {
        System.out.println(firstName + " " + lastName);
    }
    
    // override method from the Object class
    @Override
    public String toString() {
        return "Person{" + firstName + ", " + lastName + ", " + status + "}";
    }
}

// instanciate the class
Person person = new Person();       // use the "new" keyword to get a reference on a new instance 
Person person2 = person;            // person2 is a reference to the same object in memory
```

### Inheritance

All Java classes inherit implicitly from the `java.lang.Object` class.  

The `super` keyword is used to call the constructor or methods of the parent class.

```java
public class Person {
    protected String name;                         // protected access so sub-classes can access it
    public Person(String name) { this.name = name; }
    public String getName() { return name; }
    public String setName(String name) { this.name = name; }
    public String toString() { return "Person{" + name + "}"; }
}

public class Student extends Person {
    private int grade;
    public Student(String name, int grade) {
        super(name);                                 // call parent class constructor
        this.grade = grade; 
    }
    public int getGrade() { return grade; }
    public String setGrade(int grade) { this.grade = grade; } 
    
    @Override                                        // Annotation (optional but helps compiler and reader) 
    public String toString() {
        return "Student{" + name + ", " + grade + "}";
    }
}
```

### Records

Java classes come with a lot of boilerplate code : constructor, getters, setters.  
Many Java classes are POJOs (Plain Old Java object) with no logic, just constructors, getters and setters.  
Since JDK 14, Java introduced the `record` keyword to define immutable POJOs without all the boilerplate code.

A record is a special type of data structure designed for immutable POJOs, like objects read from a database.  
Java auto-generates the constructor, getters and toString() override method.  
Records are immutable so they do not have setters, the only way to set the fields is via the constructor.

```java
// declare a record
public record Student(String name, String section, int grade) {}

// instantiate a record
Student student = new Student("Bob", "A", 13);
System.out.println(student.name());                   // auto-generated getter
System.out.println(student);                          // auto-generated toString()
```


