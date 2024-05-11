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

Each of the primitive type has a corresponding Java built-in wrapper class exposing constants and methods.  
The wrapper classes are : `Byte`, `Short`, `Integer`, `Long`, `Float`, `Double`, `Character`, `Boolean`

Java also has built-in classes for commonly used data types :
- `BigDecimal` : used for floating point objects that need exact precision (float and double truncate the result)
- `String` : immutable sequence of characters, that can include unicode characters

```java
String myStr = "This cost 10\u0024 or more!";    // \u0024 is the unicode representation of '$'
myStr = "I am " + 10 + " years old";             // String supports the + operator with an integer or double
myStr = new String("Hi");                        // instanciate string by constructor with the "new" keyword

int a = Integer.parseInt("1234");                // parse a string to an int
double a = Double.parseDouble("1.234");          // parse a string to a double
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

