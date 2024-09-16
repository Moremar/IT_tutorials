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

### Java Decompiler

The Java decompiler is a utility tool provided with the JDK with the `javap` executable.  
It analyzes a `.class` file and lists all the classes with their fields and methods.

```commandline
javap -p out/production/Playground/Person.class
```


## Basic Program

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

## Primitive types

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


## Java built-in classes


### Primitive type wrappers

Each of the primitive type has a corresponding Java built-in wrapper class exposing constants and methods.  
The wrapper classes are : `Byte`, `Short`, `Integer`, `Long`, `Float`, `Double`, `Character`, `Boolean`


### String

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

String.format("%-15s %d", name, age)        // static method to format a string
"%-15s %d".formatted(name, age)             // instance method to format a string (since Java 13)
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

The `StringJoiner` class can be used to join multiple strings with a custom delimiter, prefix and suffix :

```java
StringJoiner joiner = new StringJoiner(", ", "[", "]");
joiner.add("item_1");
joiner.add("item_2");
joiner.toString();
```


### Arrays

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

### Math

The `java.util.Math` package contains common mathematic operations :
```java
// methods overloaded for multiple types (int, double, long...)
Math.abs(50);
Math.max(12, 13);
Math.min(12, 13);

// methods for double
Math.sqrt(12);
Math.pow(2, 3);      // 2^3
Math.floor(10.2);
Math.ceil(10.2);
Math.round(10.2);

Math.random();    // random double between 0 and 1

Math.PI;          // double value of Pi

// Method to prevent a numeric overflow by throwing an exception
// usual increment/decrement functions silently overflow
int i = Integer.MAX_VALUE;
i = Math.incrementExact(i);              // throw an ArithmeticException dur to integer overflow
```

### Random

The `java.util.Random` class exposes a pseudo-random numbers generator.

```java
Random random = new Random();       // random generator
Random random = new Random(1234);   // random generator with a specific seed (so the randomness is fixed)

random.nextInt();                   // pseudo-random integer in [Inger.MIN_VALUE, Integer.MAX_VALUE] ( +/- 2^32 = 4.2M)
random.nextInt(10);                 // pseudo-random integer in [0, 9]
random.nextInt(10, 20);             // pseudo-random integer in [10, 19]
random.nextDouble();                // pseudo-random double in [0.0, 1.0[
random.nextDouble(10.0);            // pseudo-random double in [0.0, 10.0[

// random streams
random.ints()                       // unlimited stream of nextInt()
random.ints(5)                      // stream of 5 elements of nextInt()
random.ints(10, 20)                 // unlimited stream of nextInt(10, 20)
random.ints(5, 10, 20)              // stream of 5 elements of nextInt(10, 20)
```

### BigDecimal

BigDecimal is an immutable class used for floating point objects that need exact precision (float and double truncate the result).  

A BigDecimal is stored internally as :
- the unscaled value : a BigInteger containing all the known digits
- the scale : the number of decimal digits in the unscaled value
- the precision : total number of known digits

```java
BigDecimal bd1 = new BigDecimal("12345.6789")     // constructor from a string
BigDecimal bd2 = BigDecimal.valueOf(0.2)          // constructor from a double, MUST BE AVOIDED AS IT MAY LOSE PRECISION

bd.unscaledValue();       // 123456789
bd.scale();               // 4
bd.precision();           // 9

bd = bd.setScale(2, RoundingMode.FLOOR);     // change the scale of the BigNumber (possible data loss if the scale was bigger)  

// operations on BigDecimal
bd1.abs();
bd1.max(bd2);
bd1.add(bd2);
bd1.multiply(bd2);
bd1.divide(bd2);
```

When performing operations on BigDecimal, some operations may throw an exception because the result is not representable as a BigDecimal.  
In that case, we should specify a **MathContext** that describe how to round the result to make it fit in a BigDecimal :
- `MathContext.UNLIMITED` : default MathContext, throws if the result has infinite decimals
- `MathContext.DECIMAL32` : round the result to fit a float (7 digits precision)
- `MathContext.DECIMAL64` : round the result to fit a double (16 digits precision)
- `MathContext.DECIMAL128` : round the result to fit twice the size of a double (34 digits precision)
- `new MathContext(60, RoundingMode.HALF_UP)` : custom MathContext with 60 digits precision

```java
BigDecimal bd1 = new BigDecimal("10");
BigDecimal bd2 = new BigDecimal("3.0");
bd1.divide(bd2);                            // throw an error because 10/3 has infinite digits
bd1.divide(bd2, MathContext.UNLIMITED);     // same error, with explicit MathContext
bd1.divide(bd2, MathContext.DECIMAL128);    // return 3.333333333333333333333333333333333 (34 digits)
```

### Dates and Time

The `java.time` package contains multiple classes to manipulate dates and times.

- `LocalDate` : an immutable date without a timezone (year / month / day)
- `LocalTime` : an immutable time without a timezone (hour / minute / second / nanosecond)
- `LocalDateTime` : an immutable date and time without a timezone (year / month / day / hour / minute / second / nanosecond)
- `ZonedDateTime` : an immutable date and time with a timezone
- `Instant` : a specific instant in the timeline, represented by its epoch seconds (seconds from `LocalDate.EPOCH`) and additional nanoseconds.  

Those classes all implement the `Temporal` interface that exposes calculation methods.

Some date and time related enums are also exposed :
- `DayOfWeek` : `MONDAY`, `TUESDAY` ...
- `Month` : `JANUARY`, `FEBRUARY`...
- `ChronoField` : `DAY_OF_WEEK`, `SECOND_OF_DAY` ... (implement the `TemporalField` interface)
- `ChronoUnit` : `DAYS`, `HOURS`, `MINUTES`, `WEEKS`, `YEARS` ... (implement the `TemporalUnit` interface)

#### LocalDate

`LocalDate` replaces the old `Date` class used before Java 8.

```java
LocalDate date = LocalDate.now();
LocalDate date = LocalDate.of(2024, 12, 31);
LocalDate date = LocalDate.parse("2024-12-31");

date.getYear();
date.getMonth();
date.getDay();
date.getDayOfWeek();
date.asStartOfDay();       // create a LocalDateTime on that day at 00:00:00
date.atTime(14, 30, 0);    // create a LocalDateTime on that day at 14:30:00
date.isLeapYear();

// we can use a TemporalField to access a specific field of the date
System.out.println(date.get(ChronoField.YEAR));
System.out.println(date.get(ChronoField.DAY_OF_YEAR));

// the withXXX methods return a new date by changing a specific value (since LocalDate is immutable)
date.withYear(2000);
date.withDayOfMonth(15);
date.with(ChronoField.DAY_OF_MONTH, 15);    // same but using a TemporalField

// operations to add/remove time to a date
date.plusYears(2);
date.plusMonths(2);
date.plusDays(2);
date.plus(2, ChronoUnit.DAYS);
date.minusDays(5);

// compare dates together
date.isBefore(date2);
date.isAfter(date2);
date.equal(date2);
date.compareTo(date2);    // 1 (bigger), 0 (equal) or -1 (smaller)

date.daysUntil(date2);                         // stream of all dates up to date2
date.daysUntil(date2, Period.ofDays(7));       // stream of all dates up to date2 by a 7 days interval
```

#### LocalTime

```java
LocalTime time = LocalTime.now();
LocalTime time = LocalTime.of(14, 30);                  // 14:30
LocalTime time = LocalTime.of(14, 30, 0, 0);            // 14:30:00.0000
LocalTime time = LocalTime.parse("14:30:00.0000");      // 14:30

time.getHour();
time.get(ChronoField.HOUR_OF_DAY);

time.plusHours(2);
time.plus(2, ChronoUnit.HOURS);
```

#### LocalDateTime

```java
LocalDateTime dateTime = LocalDateTime.now();
LocalDateTime dateTime = LocalDateTime.of(2024, 7, 12, 14, 30)        // 2024-07-12 14:30
LocalDateTime dateTime = LocalDateTime.parse("2022-05-10T15:30:45");

dateTime.getHour();
dateTime.get(ChronoField.HOUR_OF_DAY);

dateTime.plusHours(2);
dateTime.plus(2, ChronoUnit.HOURS);

dateTime.format(DateTimeFormatter.ISO_DATE_TIME);        // date time formatting : 2024-07-12T14:30:00
```

#### Instant

```java
Instant instant = Instant.now();
Instant instant = Instant.ofEpochSecond(1651395600, 12345678);

instant.getEpochSecond();
instant.getNano();

instant.get(ChronoField.MILLI_OF_SECOND);
instant.get(ChronoField.NANO_OF_SECOND);
```

#### ZoneId

The `ZoneId` class provides timezone related information.  
It replaces the old `Timezone` class used before Java 8.

```java
ZoneId.systemDefault();                // default system timezone, for ex "Asia/Tokyo"
ZoneId.getAvailableZoneIds();          // set of all available timezones

ZoneId.of("Asia/Tokyo");               // factory to create the ZoneId instance for a timezone
```

### Locale

The `Locale` class represents a geographical location with its language conventions.  
It is used to offer a different behavior based on the location of the user.  

A simple locale only has a language and a country, for example `en_US`.  
More complex locales can have extensions, or be a variant of another locale.

It can be used for date formatting, number formatting, or display text in the language of the user.

```java
Locale locale = Locale.getDefault();
Locale locale = Locale.JAPAN;
Locale locale = Locale.forLanguageTag("ja");

// format a date with a locale
LocalDateTime now = LocalDateTime.now();
DateTimeFormatter formatter = DateTimeFormatter.ofLocalizedDateTime(FormatStyle.MEDIUM)
                                               .withLocale(locale);
String formattedDateTime = now.format(formatter);        // 2 juin 2024, 16:51:09

// format a number with a locale (digits and decimal separator vary per country)
NumberFormat formatter = NumberFormat.getNumberInstance(locale);
formatter.format(12345.6789);   // "12,345.679" with Locale.JAPAN, "12 345.6789" with Locale.FRANCE ...

// currency with a locale
Currency currency = Currency.getInstance(locale);
currency.getDisplayName();                             // Euro, Yen ...
currency.getCurrencyCode();                            // EUR, JPY ...
currency.getSymbol();                                  // €, ￥ ...

// currency amount with a locale
NumberFormat formatter = NumberFormat.getCurrencyInstance(locale);    // currency formatter
formatter.format(12345.6789);   // "￥12,346" with Locale.JAPAN, "12 345,68 €" with Locale.FRANCE ...
```

#### ResourceBundle

`ResourceBundle` is an abstract class used to manage locale-specific resources in an application.  
It is often used to display text in the user's language in forms, button labels, menu items...  
It can technically also contain other data formats, like images or audio components.

The most common way to use ResourceBundle is with a bundle of properties files (a base one, and one for each supported language).  
All files of the bundle start with the same base name, have an optional suffix for the language, and the `.properties` extension.  

IntelliJ's project editor supports natively the creation of bundles with : _create a resources folder > right-click it > New > Resource Bundle_  
We can then add the resources folder to Java's path with : _right-click > mark directory as > resources root_  
IntelliJ has a `Resource Bundle Editor` plugin to easily edit the labels in all languages at the same time.
 
_CustomLabels_fr.properties_
```
# label literals
yes = oui
no = non
save = sauvegarder
edit = editer
```

```java
ResourceBundle rb = ResourceBundle.getBundle("CustomLabels", Locale.FRANCE);

rb.getBaseBundleName();           // CustomLabels
rb.getClass().getName();          // java.util.PropertyResourceBundle
rb.keySet();                      // [yes, no, save, edit]
rb.getString("save");             // sauvegarder
```

We are not limited to properties files for ResourceBundle.  
We can extend the `ListResourceBundle` class to expose any type of data, not only strings.


### Optional

`Optional<T>` is a generic class that represents an object that can have a value or no value.  
It is often used as a return type when the absence of value is a valid outcome.  
Optionals are instantiated using the `Optional.of(T)` and `Optional.ofNullable()` factory methods.  

```java
Optional<String> myOptional = Optional.empty();             // create an empty optional
Optional<String> myOptional = Optional.of("Hello");         // create an optional from a non-null value
Optional<String> myOptional = Optional.ofNullable(null);    // create an optional from a possibly null value

myOptional.isEmpty();
myOptional.isPresent();
myOptional.get();              // get the underlying value (throws if the optional is empty)
myOptional.orElse("EMPTY");    // get the underlying value if present, else a default value

myOptional.ifPresent(s -> System.out.println(s));      // execute a lambda only if the optional has a value
myOptional.ifPresent(System.out::println);             // same using a method reference
myOptional.ifPresentOrElse(                            // execute a different lambda if the optional has a value or not
        System.out::println,
        s -> System.out.println("EMPTY"));
```

### Future

The `Future` interface represents the result of an asynchronous computation (remote call, database access, long computation...).  
It has no value originally, and at some point in the future it will be assigned a value.  
It is used by asynchronous functions to immediately return a handle on the future result of their ongoing calculation.

We rarely instantiate a `Future` ourselves, instead we obtain it when calling a long-running operation.

```java
Future<Integer> futureInt = getLongRunningOperationResult();

futureInt.isDone();            // true if the result is available
futureInt.isCancelled();       // true if the result was cancelled

futureInt.get();               // block until the result is available and return it
futureInt.get(timeout, unit);  // same as get() but throws a TimeoutException if the timeout is reached
futureInt.cancel();            // interrupt the running thread
```

### Properties

The `Properties` class is a thread-safe class used to manage configuration key/value pairs.  
It inherits from `HashTable<Object, Object>` and behaves as a map with keys and values of type String.  
It exposes methods to read and write properties to a stream (file or memory).

```java
// create Properties from code
Properties props = new Properties();

// load Properties from a stream
props.load(Files.newInputStream(Path.of("myapp.properties"), StandardOpenOption.READ));

// read/write Properties
props.getProperty("age");
props.setProperty("age", "13");

// write Properties to a stream
props.store(new FileOutputStream("myapp.properties"), "My App Config");
```

## Java Collections

The Collections framework offers interfaces and implementations to manipulate common groups of objects.  

The `Collection` interface exposes some methods for common functionalities (add, remove, clear, contain, iterator...).  
The `List`, `Set` and `Queue` interfaces implement the `Collection` interface.  
The `Map` interface does not, but is still part of the Collections framework.

### Lists

Java defines the `List` interface that exposes common methods for classes implementing it :
- get the list size
- add an item
- remove an item
- check if the list is empty
- check if an element is in the list
- get the index of an item
- sort the list
- turn the list into an array
- get the item at a specific position

Different implementations of this interface have different complexity for each operation.

The `List` interface and its implementations are generic : we can specify the class of its items (default to Object).  
The items must be class objects, they cannot be primitive types.  
To use primitive types, we need to use **boxing** to use their wrapper class instead (the `Integer` class for example).
```java
Integer myInteger = Integer.valueOf(10);          // manual boxing (int -> Integer)
Integer myInteger = new Integer(10);              // deprecated boxing
Integer myInteger = 15;                           // auto-boxing (preferred)

int myInt = myInteger.intValue();                 // manual unboxing (Integer -> int)
int myInt = myInteger;                            // auto-unboxing (preferred)
```

#### ArrayList

The `ArrayList` class implements the `List` interface by using an array in memory.  
The array has a capacity, and a new array is created if more capacity becomes required.  
It can be seen as a resizable array, which the built-in array type does not allow.

```java
ArrayList<String> myList = new ArrayList<>();     // no need to specify the String type in the <>

String[] myArr = { "A", "B" };
List<String> myList = List.of(myArr);                      // create an immutable list from an array
List<String> myList = Arrays.asList(myArr);                // create a list view from an array (fixed-sized mutable)
ArrayList<String> myArrayList = new ArrayList<>(myList);   // create an ArrayList from an immutable list
ArrayList<String> myArrayList = new ArrayList<>(           // common way to initialize an ArrayList
    List.of("AAA", "BBB")
);   

myList.size();                                    // get the number of items in the list
myList.get(0);                                    // get item at a specific index
myList.toString();                                // [aaa, BBB]  (no need for a utils class to print the items)

myList.add("BBB");                                // add an item at the end of the list
myList.add(0, "AAA");                             // add an item at a specific index
myList.addAll(List.of("CCC", "DDD"));             // add multiple items at the end of the list
myList.set(0, "aaa");                             // replace the item at a specific index

myList.remove(0);                                 // delete the item at a specific index
myList.remove("Item 1");                          // delete the item with a specific value
myList.removeAll(List.of("AAA", "BBB"));          // remove multiple elements by value
myList.clear();                                   // remove all elements

myList.contains("AAA");
myList.indexOf("AAA");
myList.lastIndexOf("AAA");

myList.sort(Comparator.naturalOrder());           // sort according to a comparator
                                                  // it relies on the class to implement the Comparable interface           
myList.sort(Comparator.reversedOrder());

var myArr = myList.toArray();                    // get a Object[] from the list  
var myList = Arrays.asList(myArr);               // get an ArrayList view of an array to use ArrayList methods
                                                 // we can sort or modify items but not add or remove items
```

#### LinkedList

The `LinkedList` class is another implementation of the `List` interface using a double-ended linked list.  
It is more efficient than an `ArrayList` to add/remove elements as it does not need to shift elements or resize the array.  
It is less efficient to access elements at specific positions, as it needs to traverse the entire list.

The `LinkedList` class also implements the `Deque` interface, that can be used for FIFO and LIFO data structures.  

```java
LinkedList<String> myList = new LinkedList<>();

myList.add("Bob");                         // add an item at the end of the list
myList.addLast("Alice");                   // same
myList.offer("Alice");                     // same (for Deque interface)
myList.offerLast("Tom");                   // same
myList.addFirst("John");                   // add an item at the front of the list
myList.offerFirst("Jane");                 // same
myList.push("Mary");                       // same (stack language)

myList.remove(2);                          // remove by index
myList.remove("John");                     // remove by value
myList.remove();                           // remove the front element of the list
myList.removeFirst();                      // same
myList.pop();                              // same (stack language)
myList.poll();                             // same but allow null (queue language)
myList.pollFirst();                        // same
myList.removeLast();                       // remove the back element of the list
myList.pollLast();                         // same but allow null

myList.get(3);                             // get at a given index
myList.getFirst();                         // get the first item
myList.element();                          // same (queue language)
myList.peek();                             // same but allow null (stack language)
myList.peekFirst();                        // same
myList.getLast();                          // get the last item
myList.peekLast();                         // same but allow null (stack language)
```

### Sets

The `Set` interface defines common methods on sets, like `add`, `remove`, `contains` or `clear`.  
We can check if an item is in a set, but we cannot retrieve a specific element from a set, like a `get()` in the List interface.  
However we can iterate on all elements.

Sets cannot accept duplicates.  
To decide if an object is already in the set, it first checks its hashcode, and if found it checks equality with the `equals` method.  
By default, the `equals` method from `Object` checks memory address equality, we can override it to check fields equality.

#### HashSet

`HashSet` is the best performing implementation of the `Set` interface.    
It stores elements in a `Hashmap` under the hood, that uses the `hashcode` method of the `Object`.  
It offers O(1) performance to add/remove elements and check if an element is contained in the set.  

```java
Set<Integer> mySet = new HashSet<>();
mySet.add(1);
mySet.addAll(Arrays.asList(2, 3, 4));          // set union
mySet.retainAll(Arrays.asList(2, 3, 4));       // set intersection
mySet.removeAll(Arrays.asList(2, 3, 4));       // set asymetric difference
mySet.remove(2);
boolean myBool = mySet.contains(3);
```

#### LinkedHashSet

The `LinkedHashSet` class extends `HashSet`, and all its methods are the same.  
A LinkedHashSet is a set that maintains the insertion order of its elements.  
When iterating over its elements, they will be processed in insertion order.

#### TreeSet

The `TreeSet` class implements the `SortedSet` interface offering `first()`, `last()`, comparators...   
It also implements the `NavigableSet` interface with methods `lower(a)`, `higher(a)`, `floor(a)`, `ceiling(a)`...  

A TreeSet is a collection sorted by the natural order of its elements (or by a custom comparator).  
It uses a binary search tree (B-tree) to keep its elements in order.  
Insertion complexity is O(logN), while it is O(1) for other set implementations, because it needs to insert the element in the B-tree.  

```java
NavigableSet<Integer> myTreeSet = new TreeSet<>();
myTreeSet.add(1);
myTreeSet.add(2);
myTreeSet.add(3);
myTreeSet.first();           // smallest value in set
myTreeSet.last();            // highest value in set
myTree.pollFirst();          // smallest value in set and remove it from the set
myTree.pollLast();           // highest value in set and remove it from the set

myTreeSet.floor(2);          // highest element in the set lower or equal to a value
myTreeSet.lower(2);          // highest element in the set lower than a value
myTreeSet.ceiling(2);        // smallest element in the set higher or equal than a value
myTreeSet.higher(2);         // smallest element in the set higher than a value

myTreeSet.subset(1, 2);      // subset of all elements between a value (inclusive) and another value (exclusive)
myTreeSet.headSet(2);        // subset of all elements lower than a value
myTreeSet.tailSet(2);        // subset of all elements higher or equal to a value
```

#### EnumSet

We can create a set of enums, but Java has the `EnumSet` class that is optimized for this scenario.  
It is automatically sorted by the enum values.  
It is abstract and is instantiated via factories.  
It supports all methods from the `Set` interface.

It uses under the hood a bit-vector where each bit represents if an enum value is in the set or not.  
If the enum has up to 64 values, the `RegularEnumSet` class is used with a single 64-bit integer bit-vector.  
If the enum has more values, a `JumboEnumSet` is used instead.

```java
enum WeekDay { MON, TUE, WED, THU, FRI, SAT, SUN }

List<WeekDay> workDays = new ArrayList(List.of(WeekDay.MON, WeekDay.TUE, WeekDay.WED, WeekDay.THU, WeekDay.FRI));
EnumSet<WeekDay> myEnumSet = EnumSet.copyOf(workDays);                 // create EnumSet from list of enums
EnumSet<WeekDay> myEnumSet = EnumSet.allOf(WeekDay.class);             // create EnumSet from enum class
EnumSet<WeekDay> myEnumSet = EnumSet.complementOf(myEnumSet);          // create EnumSet from values not in another EnumSet
EnumSet<WeekDay> myEnumSet = EnumSet.range(WeekDay.MON, WeekDay.FRI);  // create EnumSet from values range

myEnumSet.forEach(System.out::println);               // iterate on all elements of the EnumSet
```

### Maps

The `Map` interface does not extend the `Collection` interface, but is part of the Java collection framework.  

#### HashMap

`HashMap` is the most common implementation of the `Map` interface, with unsorted key/value pairs.  

Some methods provide a **view** on the keys, values and entries of the map : `keyset()`, `values()` and `entrySet()`.  
Modifying these views does modify the underlying map.

```java
Map<String, Integer> myMap = new HashMap<>();
myMap.put("Bob", 12);
myMap.put("Alice", 15);
myMap.putIfAbsent("Alice", 15);          // only put the value if not already in the map
myMap.get("Bob");                        // access the value for a key (null if not found)
myMap.getOrDefault("Bob", 0);            // access the value for a key (default value if not found)
boolean deleted = myMap.remove("Bob");   // delete an item by key

// iterate on the map
myMap.forEach((k, v) -> System.out.println(k + " : " + v));

// add a value in the map by applying a function to the key and the existing value
myMap.compute("Bob", (k, v) -> k % 2 == 0 ? 0 : 1);

// same as compute() but only apply if the key is absent/present in the map
myMap.computeIfAbsent("Bob", k -> k.length() % 2 == 0 ? 0 : 1);
myMap.computeIfPresent("Bob", (k, v) -> k.length() % 2 == 0 ? 0 : 1);

// set the value if the key is absent, else apply a function to the old and new values
myMap.merge(""Bob", 3, Integer::sum);

// views on the keys, values and entries of the map
Set<String>                     myKeys    = myMap.keySet();
Collection<Integer>             myVals    = myMap.values();
Set<Map.Entry<String, Integer>> myEntries = myMap.entrySet();
myKeys.remove("Bob");                                      // remove the element from myMap
myEntries.removeIf(entry -> entry.getValue() % 2 != 0);    // remove the elements from myMap
```

#### LinkedHashMap

`LinkedHashMap` extends `HashMap` and keeps the key/value pairs sorted by insertion order.  
Its methods are the same as `HashMap`, but the iteration order is different.

#### TreeMap

`TreeMap` implements the `SortedMap` interface and keeps the key/value pairs sorted.  
It makes use of a binary search tree (B-tree) to maintain the order, so the insertion has O(logN) complexity.

`TreeMap` implements `NavigableMap`, that exposes methods similar to `NavigableSet` : `headMap`, `tailMap`, `submap`, `firstEntry`, `lastEntry` ...

#### EnumMap

We can create a map with enum keys, but Java has the `EnumMap` class that is optimized for this scenario.  
Unlike `EnumSet`, it is not abstract and can be instantiated directly.  
It is naturally ordered by the values of the enum.  
It supports all methods from the `Map` interface.

```java
enum WeekDay { MON, TUE, WED, THU, FRI, SAT, SUN }

Map<WeekDay, String[]> employeeMap = new EnumMap<>(WeekDay.class);     // empty EnumMap
employeeMap.put(WeekDay.MON, new String[]{ "Bob", "Alice" });
employeeMap.put(WeekDay.WED, new String[]{ "Bob" });

employeeMap.forEach((k, v) -> System.out.println(k + " : " + Arrays.toString(v)));
```


### Collections class

The `Collections` class contains some helper methods on collections.  
It pre-dates the support of static and default methods in interfaces, and now some of its functionalities are implemented in the interfaces.  

```java
List<Double> myList;
myList = Collections.emptyList();
myList = Collections.singletonList(2.5);
myList = Collections.nCopies(10, 2.5);           // create a list with a single value repeated multiple times
myInt = Collections.frequency(myList, 2.5);      // number of occurrences of a value in the collection

Collections.shuffle(myList);                     // in-place shuffle
Collections.reverse(myList);                     // in-place reverse
Collections.rotate(myList, 3);                   // in-place rotation of a specific shift (negative to shift left)
Collections.swap(myList, i, j);                  // in-place swap of 2 elements
Collections.sort(myList);                        // in-place sort of a list of Comparable (now replaced by the interface method)
Collections.sort(myList, myComparator);          // in-place sort of a list with a custom comparator

myBool = Collections.binarySearch(myList, 2.5, myComparator);   // search in a sorted list (similar to the method in Arrays)
myBool = Collections.disjoint(myList, myList2);                 // true if the 2 lists have no element in common

myDouble = Collections.min(myList, myComparator); 
myDouble = Collections.max(myList, myComparator); 

// Unmodifiable views of collections (cannot add, remove, update, sort elements...)
Collections.unmodifiableList(myList);
Collections.unmodifiableSet(mySet);
Collections.unmodifiableMap(myMap);
```

### Comparable and Comparator

`Comparable<T>` is an interface that allows to compare an instance with an object of the same class or another class.  
It contains only the `compareTo(T)` method.

It is used by `List<E>` for example when calling the sort function.  
We can only sort a list of objects from a class that implements Comparable.

`Comparator<T>` is another interface that allows to compare 2 objects of the same type.  
It only contains the `compare(T, T)` method.  
Comparators are often created to offer multiple comparison logics for 2 objects of the same class.  
Common examples are `Comparator.naturalOrder()` and `Comparator.reverseOrder()`. 

## Iterators

The `Iterator` interface defines an object offering a convenient way to traverse an iterable collections.  
`ListIterator` is a specialized implementation to iterate over a list.  

`Iterator` can iterate forwards only, and exposes the following methods :
- `hasNext()` : true if there are more items to iterate on
- `next()` : value of the next item
- `remove()` : remove the current item

`ListIterator` adds some methods :
- `hasPrevious()` : true if there are more items before the current iterator
- `previous()` : value of the previous item
- `add(item)` : add an item at the iterator position

```java
LinkedList<String> myList = new LinkedList<>();
myList.add("AAA");
myList.add("BBB");
myList.add("CCC");

ListIterator it = myList.listIterator();
while (it.hasNext()) {
    System.out.println(it.next());
}
```


### Enums

An enum is a special class where each enum value is an instance of the class.  

```java
public enum DayOfWeek {
    MON, TUE, WED, THU, FRI, SAT, SUN
}

DayOfWeek day = DayOfWeek.WED;
day.name();                                   // get the enum value label
day.ordinal();                                // get the enum value index in its enum class

DayOfWeek[] allDays = DayOfWeek.values();     // array of all enum values 
```

An enum is a special class where each enum value is an instance of the class.  
It is possible to define custom methods inside an enum :

```java
public enum DayOfWeek {
    MON, TUE, WED, THU, FRI, SAT, SUN;
    
    public boolean isWeekend() {
        return this == SAT || this == SUN;
    }
}

DayOfWeek day = DayOfWeek.SAT;
boolean isWeekend = day.isWeekend();
```

We can specify a constructor for an enum class, which must be private and gets called for each value of the enum.  
This is useful if we want to add some fields to the enum, we can pass them to the constructor :

```java
public enum GenerationE {
    GEN_Z(2001, 2020),
    MILLENIAL(1981, 2000),
    GEN_X(1961, 1980),
    BABY_BOOMER(1941, 1960);
    
    private final int startYear;
    private final int endYear;
    
    GenerationE(startYear, endYear) {
        this.startYear = startYear;
        this.endYear = endYear;
    }
    
    public int getStartYear() { return this.startYear; }
    public int getEndYear() { return this.endYear; }
}
```
Under the hood, an enum is just a class extending the `java.lang.Enum` class, with a static final field for each enum value.  
This can be observed with the `javap` Java disassembler, along with its constructor, fields, and methods.


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

### Sealed classes

Since Java 17, the `sealed` modifier can be used for classes and interfaces, bother outer and inner.  
It allows to limit the classes that can extend this class or interface.  

It requires the `permits` keyword to specify which classes can extend the class.  
Subclasses need to be explicitly listed, and must be in the same package.  
Subclasses also need to be either `final`, `sealed` or `non-sealed`.

```java
public sealed class Person permits Student {
    [ ... ]
}

public final class Student extends Person {
    [ ... ]
}
```

The only case a sealed class does not need to permit its subclass is if the subclass is a nested class of the sealed class.  
This is only true if there are no other permitted subclasses : it there are, the nested class must be listed along with them.

## Type inference

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

Java has checked and unchecked exceptions that extend the `Exception` class.  
Checked exceptions that a function may throw are specified in the function signature.  
Any function calling such a function needs to handle the exception either with try/catch or by adding the exception to its signature.

On the other hand, unchecked exception extend `RuntimeException` and are not specified in the function signature.  
They can still be caught in a try/catch block by their exception class or one of its parents.

Common checked exceptions are :
- `IOException` failure in an I/O operation (reading a file, stream, database ...)
- `ParseException` : failure to parse an object from a string
- `InterruptedException` : interruption of a thread while waiting
- `ClassNotFoundException` : attempt to access a class by reflection that was not loaded

Common unchecked exceptions are :
- `NullPointerException` : attempt to access a method or field on a null reference
- `IllegalArgumentException` : when an argument is not valid for a function (negative integer, date in the future...)
- `IndexOutOfBoundsException` : illegal index access in a data structure

```java
try {
    System.console().readLine("Your name: ");   // throw a NullPointerException when run in IntelliJ IDEA
} catch (NullPointerException e) {
    System.out.println("No console available.");
} finally {
    // code to execute even on exception
}
```

If a class implements `Closeable` or `AutoCloseable`, it can use the try-with-resource structure.  
The variable is declared in the `try` instruction, and closed automatically after it.

```java
try (FileReader reader = new FileReader("test.txt")) {
    // do something
} catch (FileNotFoundException | NullPointerException e) {       // can have multiple exception types in a catch block
    throw new RuntimeException(e);
} catch (Exception e) {
    throw new RuntimeException(e);
}
```

Note that a try/catch or try-with-resource structure can have multiple catch blocks.  
They are evaluated in the order they appear in the code, and must be ordered from the most specific to the most specific exception.


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


## File Manipulation

### java.io (legacy package)

The `java.io` package has been available since Java 1, and is now considered legacy.  
It is still usable, but it has limited functionalities and does not handle well exceptions.

The `File` class gives access to a file handler to perform OS-like operations.  
It is just a file handle, so it does not open/close the file on disk.  
This must not be confused with a file resource, that represents the actual data inside the file.

```java
File file = new File("");                  // file handle to the execution folder
File file = new File("docs/test.txt");     // file handle to a given file (relative path)
File file = new File("/docs/test.txt");    // file handle to a given file (absolute path)

file.exists();
file.isDirectory();
file.isFile();
file.getAbsolutePath();
file.listFiles();                          // array of File objects if the file is a directory

file.canRead();
file.canWrite();
file.canExecute();

file.createNewFile();                      // return a success boolean
file.delete();                             // return a success boolean

// rename a file (deprecated, use Path instead)
File oldFile = new File("old.txt");
File newFile = new File("new.txt");
if (oldFile.exists()) {
    boolean success = oldFile.renameTo(newFile);
}
```

The `FileReader` class implements the `AutoCloseable` interface via its abstract parent class `Reader`.  
By default it reads integers from a file, corresponding to the char value of each character in the file.  
It uses a buffer to read multiple integers from the file at each physical disk read to improve performance.
```java
// read data from a file int by int
try (FileReader reader = new FileReader("test.txt")) {
    int data;
    while ( (data = reader.read()) != -1 ) {
        System.out.println( (char) data );
    }
} catch (IOException e) {
    e.printStackTrace();
}

// read data from a file as an array of char
try (FileReader reader = new FileReader("test.txt")) {
    char[] data = new char[1000];
    int charsRead;
    while ( (charsRead = reader.read(data)) != -1 ) {
        String content = new String(data, 0, charsRead);
        System.out.println( "%s (%d chars)", content, charsRead );
    }
} catch (IOException e) {
    e.printStackTrace();
}
```

Java uses the `InputStream` interface to represent a stream or characters or bytes.  
The `FileInputStream` is the implementation for bytes coming from a file.  
Its `read()` method corresponds to a physical read, so it is usually wrapped in a `BufferedInputStream` for efficiency.  
The `FileReader` class uses an `InputStream` under the hood to read the content of the file.

```java
// use a BufferedReader to improve efficiency by reducing physical reads
// read data from a file as an array of char
try (BufferedReader reader = new BufferedReader(new FileReader("test.txt"))) {

    // read lines one by one
    String line;
    while ( (line = reader.readLine()) != null ) {
        System.out.println( line );
    }
    
    // read all lines at once as a stream (from Java 8)
    reader.lines().forEach(System.out::println);
    
} catch (IOException e) {
    e.printStackTrace();
}
```

We can also use a `Scanner` to read a file, exposing the same methods as when reading from `System.in`.  
`Scanner` has many overloaded constructors, including ones taking as input a `File`, `Path`, `FileReader`...  
It them leverages the new classes in `system.nio` package under the hood.

```java
try (Scanner scanner = new Scanner(new File("test.txt))) {
    while (scanner.hasNextLine()) {
        System.out.println(scanner.nextLine());
    }
} catch (IOException e) {
    e.printStackTrace();
}
```

To write a file, we use an implementation of the `Writer` interface, among the multiple variations available :
- `PrintWriter` : exposes the `write` method to add a string, and the `println` method that appends a system-specific newline and flushes
- `FileWriter` : exposes the `write` method to add a string
- `BufferedWriter` : better performance to wrtie large amounts of text to a file, can wrap other writer types

```java
try (PrintWriter writer = new PrintWriter("test.txt")) {
    writer.println(line1);
    writer.println(line2);
    writer.printf("%-12d", 13);        // print a number with a fixed size (the - means left-aligned)
}
```

### java.nio (new package)

The `java.nio` package was added in Java 7 to make file manipulation easier.  
It supports asynchronous file IO operations, symbolic links, better file locking...  
It should be used instead of `java.io` in every application using Java 7+.

The `Path` interface is the successor of the `File` class for file handlers.  
The `Paths` class exposes the `Paths.get(str)` static method to create a Path instance.  
Since Java 11, we can use an interface static method instead with `Path.of(str)`.

The `Files` class exposes some static methods to manipulate files (create, delete, read, write, check metadata...).  
Many of those methods use a `Path` parameter to specify the file to manipulate.

```java
Path path = Paths.get("docs/test.txt");           // before Java 11
Path path = Path.of("docs/test.txt");             // since Java 11

path.getFileName();
path.getParent();
path.isAbsolute();
path.toAbsolutePath();
path.getRoot();                                    // root of the absolute path (like / on Linux or C:\ on Windows)
path.getName(i);                                   // i-th folder name of an absolute path

Files.isReadable(path);
Files.isWritable(path);
Files.isExecutable(path);


// rename / copy / delete a file
Path newPath = Path.of("new.txt");
try {
    Files.copy(path, newPath);
    Files.move(path, newPath);
    Files.delete(newPath);
}

Files.exists(path);
Files.createFile(path);                           // return void, exception on failure
Files.createDirectory(path);                      // create one level of directory (the parent directory must exist)
Files.createDirectories(path);                    // create one or more level of directories
Files.delete(path);                               // throw IOException on failure (file does not exist, non-empty dir...)
Files.deleteIfExists(path);
Files.readAttributes(path);                       // map of attributes (size, creation time last access time, is directory...)


// write a string to a file
Files.writeString(path, """
    First Line.
    Second Line.""");

// write a string to a file with options
Files.writeString(path, "hello",
    StandardOpenOption.CREATE,                    // create the file if needed
    StandardOpenOption.APPEND);                   // append instead of replacing

// writes all strings in an iterable
Files.write(path, iterableObj);

// read from a file
Files.readString(path);                           // get the entire file as a string
Files.readAllBytes(path);                         // get the entire file as an array of bytes
Files.readAllLines(path);                         // get all lines of a file
Files.lines(path);                                // get all lines of a file as a stream
```

Some methods return a stream of Path instances, and must be used with try-with-resource to ensure that they get closed :
- `Files.list(path)` : stream of files and directories contained in a given directory (`ls` or `dir` command)
- `Files.walk(path, depth)` : similar to `Files.list(path)` but recursive for depth > 1 (depth-first traversal)
- `Files.find(path, depth, predicate)` : similar to `Files.walk(path, depth)` but filters the stream on a predicate
- `Files.newDirectoryStream(path, glob)` : similar, but uses a GLOB to filter instead of a predicate (for example `*.txt`)

```java
// print the content of a folder
try (Stream<Path> paths = Files.list(path)) {
    paths.forEach(System.out::println);
} catch (IOException e) {
    e.printStackTrace();
}

// print the content of a folder and all its sub-folders up to a depth of 3
try (Stream<Path> paths = Files.walk(path, 3)) {
    paths.forEach(System.out::println);
} catch (IOException e) {
    e.printStackTrace();
}

// print all files (and not directories) in a folder and all its sub-folders up to a depth of 3
try (Stream<Path> paths = Files.find(path, 3, (path, attributes) -> Files.isRegularFile(path))) {
    paths.forEach(System.out::println);
} catch (IOException e) {
    e.printStackTrace();
}
```

The `Files.walkFileTree()` is an alternative to `Files.walk()` for file traversal.  
Instead of returning a stream, it traverses files and folders in a folder and apply a visitor during irs traversal.  
Overriding the visitor methods exposes a hook during file visit, before/after directory visit and on file visit failure.

```java
// define a file visitor class that performs an action during the traversal
private static class CustomFileVisitor extends SimpleFileVisitor<Path> {

    @Override
    public FileVisitResult visitFile(Path path, BasicFileAttributes attrs) throws IOException {
        System.out.println("Traversing file " + path.getFileName());
        return FileVisitResult.CONTINUE;
    }

    @Override
    public FileVisitResult preVisitDirectory(Path path, BasicFileAttributes attrs) throws IOException {
        System.out.println("Before traversal of directory " + path.getFileName());
        return FileVisitResult.CONTINUE;
    }
}

// traverse the files using this visitor
FileVisitor<Path> visitor = new CustomFileVisitor();
try {
    Files.walkFileTree(path, visitor);
} catch (IOException e) {
    e.printStackTrace();
}
```

### Random Access Read/Write

Usually files are read or written from the beginning to the end, but we may sometimes need to write or read a binary file at specific offsets.  
This is possible with the `RandomAccessFile` that uses a **file pointer** to keep track of its location in the file.  
It behaves like a large array of bytes where we can read or write any byte.

Random access files can be used together with an index, to easily retrieve rows in a big files without scanning the entire file.  
The index can be at the beginning of the file, at the end of the file or in a separate file.  

A common structure for the index is :
- the row count (4-byte integer)
- the map of record ID (8-byte long) and their position in the file (8-byte long)

For fixed-size rows, the index is sometimes not needed if we can use the row ID instead.

```java
// write a binary file with RandomAccessFile
try (RandomAccessFile file = new RandomAccessFile("test.dat", "rw")) {
    file.seek(4);              // move the file pointer to position 4 (beginning of the 5th byte of the file)
    file.writeUTF("Hello");    // write a string to the file (and move the file pointer to the next byte)
    file.writeInt(2);          // write an int to the file (and move the file pointer to the next byte)
    file.writeInt(222222);     // write a long to the file (and move the file pointer to the next byte)
}

// read a binary file with RandomAccessFile
try (RandomAccessFile file = new RandomAccessFile("test.dat", "r")) {
    String str = file.readUTF();    // read a string from the file (and move the file pointer to the next byte)
    int i = file.readInt();         // read an int from the file (and move the file pointer to the next byte)
    long l = file.readInt();        // read a long from the file (and move the file pointer to the next byte)
}
```

### Serialization

Primitive types can be written to files using the `DataOutputStream` class.  
It wraps another output stream (for example a `BufferedOutputStream` or directly a `FileOutputStream`).  
It allows to write primitive types and let the underlying output stream write the bytes to the file.  

```java
try ( DataOutputStream dataStream = new DataOutputStream(
                new BufferedOutputStream( new FileOutputStream("test.txt") ) ) ) {
                
    // write primitive types
    dataStream.writeInt(12);
    dataStream.writeLong(123456789);
    dataStream.writeBoolean(true);
    dataStream.writeChar('Z');
    dataStream.writeFloat(1.5);
    dataStream.writeDouble(3.14);
    dataStream.writeUTF("Hi friend");
    
    dataStream.size();      // total size of data written to the output data stream (in bytes)
}
```

The equivalent to read primitive types from a file is the `DataInputStream` class :

```java
try ( DataInputStream dataStream = new DataInputStream(Files.newInputStream("test.txt")) ) {
                
    // read primitive types
    dataStream.readInt();
    dataStream.readLong();
    dataStream.readBoolean();
    dataStream.readChar();
    dataStream.readFloat();
    dataStream.readDouble();
    dataStream.readUTF();
    
    dataStream.size();      // total size of data written to the output data stream (in bytes)
}
```

The `Serializable` interface is used to mark the classes that can be serialized to a file.  
It does not include any method, and only means that the class can be serialized by copying its fields.  
All non-static fields of a serializable class must be serializable.

Serializable objects can be written to files with the `writeObject(o)` method of the `ObjectOutputStream` class.  
They can then be read from the file using the `readObject(o)` method of the `ObjectInputStream` class.  
This avoids to write/read manually all the primitive fields of the class.

Java computes under the hood a serial version ID for each class that implements the Serializable interface.  
This serial version ID is included in each serialized object of that class.  
When deserializing, Java ensures that the serial version ID in the serialized object corresponds to the class we are deserializing.  
If the class definition has changed (additional field, field type modification...) then the class has a different serial version ID.  
This causes an exception during deserialization.

The serial version ID generated automatically by Java may not be compatible between JVMs.  
For objects serialized in a JVM to be deserializable in another JVM, we can specify the serial version ID manually.  
We can set its version to any long, as long as it is different from all our other serializable classes and changes when the class structure is updated.
```java
private final static long serialVersionUID = 1L;
```

We can override the methods that Java uses to serialize and deserialize objects of a class.  
This can either enrich the default behavior, or completely replace it.  
We can also use the `serialVersionUID` field to have a different logic depending on the serialized version, to add inter-version compatibility.

```java
// example of an override of readObject(stream) that only enriches the default deserialization 
@Serial
private void readObject(ObjectInputStream stream) throws IOException, ClassNotFoundException {
    stream.defaultReadObject();     // populate the fields by Java default deserialization
    myValid = myInt > 5;            // custom logic to modify the fields    
}

// example of an override of writeObject(stream) that uses a custom serialization
@Serial
private void writeObject(ObjectOutputStream stream) throws IOException {
    stream.writeInt(myInt);
    stream.writeUTF(myName);    
}
```

### WatchService

The `WatchService` interface allows to monitor directories and files for changes.  
It can be used to update file lists in a file manager when files are created, modified, or deleted.

```java
WatchService watchService = FileSystems.getDefault().newWatchService();

// register a folder to watch for events
Path dirToWatch = Paths.get("path/to/directory");
dirToWatch.register(watchService, StandardWatchEventKinds.ENTRY_MODIFY);

// poll for events in a blocking way with the take() method
WatchKey watchKey;
while ((watchKey = watchService.take()) != null) {

    // perform an action on each event
    watchKey.pollEvents().forEach(event -> {
        System.out.println(event.kind());
        System.out.println(event.context());
    });
    
    // need to reset the watchKey so we can continue monitoring for further changes
    watchKey.reset();
}

// when no longer used we should close it so it can release its resources
watchService.close();
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

#### Class Initializer Block

A class can have one or more class initializer blocks.  
They are blocks of code directly specified in the class definition, that get executed before any constructor code.  
They can be used to initialize default fields values for example.

We can also specify one or more static initializer blocks.  
They get executed only once at the first class reference, in the order they appear in the code.

```java
class Person {

    private String name;
    private int age;
    
    // static initializer block
    static {
        System.out.println("In the static initializer block");
    }
    
    // instance initializser block
    {
        System.out.println("In the instance initializer block");
        this.name = "Bob";
        this.age = 20;
    }
    
    Person() {}
    Person(String name) { this.name = name; }
    Person(String name, int age) { this.name = name; this.age = age; }
}
```


### Inheritance

All Java classes inherit implicitly from the `java.lang.Object` class.  

The `super` keyword is used to call the constructor or methods of the parent class.

Methods in the base class can be overridden in the child class with the `@Override` annotation.  
Methods marked with the `final` modifier cannot be overridden by child classes.

Static methods in the base class can be hidden in the child class by defining a static method with the same name.  
When called on an instance, the static method of the reference type (declared type, not effective type) is used.  
It is recommended to always call static methods via their class name, not via an instance.  
Making a static method `final` prevents child classes to hide it (but that usually suggests a bad design).

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

### Abstraction and Interfaces

Class hierarchy allows the abstraction of concrete classes under a common base class.  
Java offers **abstract classes** and **interfaces** to represent this abstraction.

An abstract class uses the `abstract` modifier, it is a class that has at least one abstract method.  
An abstract method uses the `abstract` modifier, it is a method that has a signature but no concrete body.  
An abstract class can be extended, but not instantiated, because it is not fully implemented.  
An abstract class can have a constructor that is called by the child classes.

An interface is an abstract class that has only abstract methods and no fields.  
It only consists of a set of methods that child classes need to implement.  
Fields of an interface are interface-level constants (static public and final), no need to use those keywords explicitly.  
Methods of an interface are public and abstract by default, so no need to explicitly write it.

A Java class can only extend a single class, but it can implement any number of interfaces.  

An interface can extend another interface (adding abstract methods to it) but cannot implement an interface.  
An interface can be implemented by a class, a record or an enum.  

Until JDK8, interfaces could only have abstract public methods.  
This caused a common problem : when we want to add a method to an interface, all classes implementing it must be updated.  
Java 8 introduced **concrete default methods**, to specify a default behavior for a method, and only relevant implementation can override it.

Java 8 also introduced **static methods on interfaces**, that can be called using the interface name as identifier, for example `Comparator.naturalOrder()`.  
This avoids creating a separate helper class to contain these static methods.

JDK9 introduced **concrete private methods**, both static and non-static, that can be used only from concrete methods in the interface.

### Nested Classes

There are 4 types of nested classes in Java :

- **Static Nested Class**
  - declared in the class body
  - accessed through the class name identifier
  - the outer class and inner class can access each-other's private attributes
  - static nested classes are inherited by subclasses (so we can access them using a subclass identifier)
  - it can be used to define a Comparator specific to a class for example
```java
public class Student {
    public static class StudentComparator<T extends Student> implements Comparator<Student> {
        @Override
        public int compare(Student s1, Student s2) {
            return s1.name.compareTo(s2.name);
        }
    }
    private String name;
    private Student(String name) { this.name = name; }
}

var comparator = new Student.StudentComparator<Student>();
```


- **Instance Class**
  - declared in the class body
  - accessed through an instance of the  class
  - usually instance classes are not accessed from outside the outer class
  - if the outer and inner class have a field with the same name, we access the outer one with `Outer.this.name`
```java
public class Student {
    public class StudentComparator<T extends Student> implements Comparator<Student> {
        @Override
        public int compare(Student s1, Student s2) {
            return s1.name.compareTo(s2.name);
        }
    }
    private String name;
    private Student(String name) { this.name = name; }
}

var comparator = (new Student("AAA")).new StudentComparator<Student>();
```


- **Local Class**
  - declared within a method body
  - no access modifier
  - not accessible from outside the method
  - can access private fields of the enclosing class
```java
public static void sortByName(List<Student> students) {
    class NameComparator implements Comparator<Student> {
        @Override
        public int compare(Student s1, Student s2) {
            return s1.getName().compareTo(s2.getName());
        }
    }
    sort(new NameComparator());
}
```


- **Anonymous Class**
  - unnamed class
  - declared and instantiated in the same statement
  - use the `new` keyword, then the name of the class to extend or an interface to implement
  - used a lot less since Java 8 introduced lambda expressions
```java
students.sort(new Comparator<Student>() {
    @Override
    public int compare(Student s1, Student s2) {
        return s1.getName().compareTo(s2.getName());
    }    
});
```


## Lambda Function

A Lambda function is an anonymous function with a simplified syntax.  

A **functional interface** is an interface with exactly one abstract method.  
It can use the `@FunctionalInterface` annotation to make it explicit.  
Java comes with many built-in functional interfaces, like `Comparator<T>` or `Comparable<T>`.

Functional interfaces are perfect targets for lambda functions.  
Many methods use functional interfaces for their method parameters.  
Instead of providing an instance of a functional interface, we can provide a lambda, and Java infers the method and the parameter types.
```java
students.sort((s1, s2) -> s1.getName().compareTo(s2.getName()));   // lambda replacing Comparator<Student>
```

Lambda functions can use variables of the outer scope only if they are final or effectively final (assigned only once).

Functional interfaces often include default methods to chain method calls.  
It allows to combine multiple transformations into a single instance of the functional interface :
```java
// chaining with the UnaryOperator functional interface
UnaryOperator<String> upper = String::toUpperCase;
var combined = upper
        .andThen(s -> s + " Jr.")
        .andThen(s -> s + " " + new Random().nextInt(10))
        .andThen(s -> s.split(" "));
System.out.println(Arrays.toString(combined.apply("Tom")));   // [ "TOM", "Jr.", "7" ]

// chaining with the Predicate functional interface
Predicate<String> check = s -> s.contains("t");
var combinedCheck = check
        .or(s-> s.equalsIgnoreCase("DEFAULT"))
        .and(s -> s.endsWith("s"))
        .negate();
System.out.println(combinedCheck.test("Hello"));
```

### Java built-in Functional Interfaces

- `Consumer<T> ` : defines `void accept(T)`
  - represent an operation accepting a single input and returning no result
  - the processing of the method is expected to use side-effects, like updating a DB or sending a message.
  - can be used for example in the `forEach()` method of a list
  - its variant with 2 parameters is called `BiConsumer<T, U>`
  ```java
  students.forEach((s) -> { System.out.println(s); });
  students.forEach(s -> System.out.println(s));          // variant with simplified syntax
  students.forEach(System.out::println);                 // variant with a function reference instead of lambda
  ```


- `Runnable` : defines `void run()`
  -  represent a task that can run asynchronously and returns no value
  - often used when creating a new thread
  ```java
  Thread thread = new Thread(() -> { System.out.println("New thread running") });
  thread.start();
  ```


- `Callable<T>` : defines `T call()`
  -  represent a task that can run asynchronously and returns a value
  - often used when creating a new thread
  - similar to Runnable but with a return value
  ```java
  Callable<Integer> callable = () -> 42;
  FutureTask<Integer> futureTask = new FutureTask<>(callable);
  Thread thread = new Thread(futureTask);
  thread.start();
  Integer res = futureTask.get();     // wait for the result
  ```


- `Comparable<T>` : defines `compareTo(T)`
  - define an ordering between instances of a class
  - used by the sort methods of many data structures like lists and arrays
  ```java
  List<Person> friends = new ArrayList<>(Arrays.asList(
      new Person("John", 25),
      new Person("Lea", 23),
      new Person("Jade", 31),
  ));
  Collections.sort(friends);
  ```
  

- `Predicate<T>` : defines `boolean test(T)`
  - define a test on instances of a class that can be either true or false
  - used for filtering objects in collections
  - its variant with 2 parameters is called `BiPredicate<T, U>`
  ```java
  List<Integer> list = new ArrayList<>(Arrays.asList(1, 2, 3, 4, 5));
  Predicate<Integer> isEven = num -> num % 2 == 0;
  list.removeIf(isEven);
  ```


- `Function<T, R>` : defines `R apply(T)`
  - represent an operation on one object returning an object
  - variant with the parameter and the return value of the same class is `UnaryOperator<T>`
  - variant with 2 parameters is `BiFunction<T, U, R>`
  - variant with 2 parameters of the same class and a return value of the same class is `BinaryOperator<T>`


- `Supplier<T>` : defines `T get()`
  - represent a factory that takes no argument and returns an object
  ```java
  Supplier<Integer> randomIntSupplier = () -> new Random().nextInt(100);
  System.out.println("Random number: " + randomIntSupplier.get());
  ```


## Generic Types

Generic types allow to define a template that can apply to multiple underlying classes or types.  
For example `List<E>` is a generic interface.  
When instanciating a generic type, we need to specify its parametrized type, for example `List<String>`.  

Classes, interfaces and records can be generic.  
A method can also be generic.

A generic type can specify one or more parametrized types.  
Parametrized types can be forced to extend or implement a specific class with the `extends` keyword.

```java
class Team<T extends Player>  {
    private String teamName;
    private List<T> teamMembers = new ArrayList<>();
    
    public Team(String n) {
        name = n;
    }
    
    public addTeamMember(T t) {
        teamMembers.add(t);
    }
    
    [...]
}
```

Note that `List<Dog>` does not extends `List<Animal>` even if `Dog` extends `Animal`.  
This is a problem if we have a method that expects a parameter of type `List<Animal>`.   
To address this issue, we can use a **generic method** that takes a parameter of type `List<T>`.  
Alternatively, we can use a **wildcard parameter** in the method.

```java
// generic method
public static <T extends Animal> void printAnimals(List<T> animals) {
    for (T animal : animals) {
        System.out.println(animal);
    }
}

// wildcard parameter
public static void printAnimals(List<? extends Animal> animals) {
    for (T animal : animals) {
        System.out.println(animal);
    }
}

List<Animal> animals = new ArrayList<>();
List<Dog> dogs = new ArrayList<>();

// we can call the generic method or the wildcard method with a list of animals or any of its subtypes
printAnimals(animals);
printAnimals(dogs);
```

The compiler performs **type erasure** when compiling code using generic types.  
It means that it replaces the generic type by Object or by the upper bound if specified with a `extends` keyword.  
This can create some conflicts between methods that have the same type erasure.  
For example, these 2 methods cannot be defined at the same time, because after type erasure they have the same signature :
```java
// method on a list of strings
public void print(List<String> strings) {
    [ ... ]
}

// method on a list of integers
public void print(List<Integer> numbers) {
    [ ... ]
}

// instead of the 2 above methods with same erasure, we can use a single method with a wildcard
// if we need different logic for String and Integer we use instanceof
public void print(List<?> list) {
    for (var item : list) {
        if (item instance of String s) {
            [ ... ]
        } else if (item instance of Integer i) {
            [ ... ]
        }
    }
}
```


## Java Streams

Streams are a feature introduced with Java 8 to compute successive operations on a data set.  
Streams are a mechanism to define a sequence of operations before actually executing them.

Streams do not contain any data, they take as input a data source (a collection, an input file, a database query result...).  
They are similar in their purpose to a SQL query, defining how to transform, filter and order data.

Streams implement the `Stream<T>` generic interface, exposing methods like `map()`, `filter()`, `sorted()`, `reduce()` ...  
The stream operations make heavy use of functional interfaces and lambdas.  
A combination of these operations is called a **stream pipeline**.  
It helps to write readable code, by specifying what operations to perform and letting Java decide the implementation.

Most operations in a stream pipeline are intermediate operations, that return a Stream object, so they can be chained.  
The last operation needs to be a terminal operation, like `forEach()`, `toList()` or `reduce()`.

```java
List<Integer> ints = new ArrayList<>(25);
for (int i = 0; i < 26; i++) {
    ints.add(i);
}

// create a pipeline with intermediate operations that do not get executed yet
var pipeline = ints.stream()
        .distinct()
        .filter(i -> i % 2 != 0)
        .map(i -> i * 10)
        .sorted()
        .limit(5);
        
// call a terminal operation on the pipeline so the entire pipeline gets processed
var result = pipeline.toList();
```

Streams are lazy, they are evaluated on source data only when a terminal operation is called.  
Stream computation is optimized : before execution, the stream implementation checks the entire workflow and optimizes it as it wants.  
It guarantees the final result, but not the intermediate steps to reach it (it may discard, combine or reorder some steps for performance).

A stream can only be consumed once, we cannot call multiple times a terminal operation on the same stream pipeline.

### Stream Sources

Multiple sources can be used by a stream :

- **collections** : with the `stream()` instance method in the `Collection` interface

- **arrays** : with the `Arrays.stream(arr)` static method

- **individual objects** : with the `Stream.of(obj1, obj2, ...)` static method

- **2 streams** : with the `Stream.concat(stream1, stream2)` static method

- **range of values** : with the `IntStream.range(startVal, endVal)` static method

- **generator method** : with the `Stream.generate(provider)` static method to generate an infinite number of elements, that can be limited later :
```java
Random random = new Random();
Stream.generate( () -> random.nextInt(5) )      // infinite sequence of random numbers between 0 and 4
      .filter(i -> i % 2 == 1)                  // keep only odd numbers
      .limit(10)                                // stop the infinite stream after 10 values post-filter
      .forEach(System.out::print);  
```

- **iterative method** : with the `Stream.iterate(seed, unaryOp)` static method to generate an infinite number of elements starting with a seed and
  generating all following elements by applying a unary function on it
```java
InStream.iterate(1, i -> i + 2)             // infinite sequence of odd integers 
        .limit(10)                          // stop the infinite stream after 10 values
        .forEach(System.out::println);
        
InStream.iterate(1, i -> i < 100, i -> i + 2)     // stream with a predicate that stops as soon as it returns false 
        .forEach(System.out::println);
```

### Intermediate Stream Operations

Intermediate stream operations apply on a stream and return a stream, potentially with a different underlying element type.  
They can be chained to apply successive transformations and filtering to the source data.

#### Filtering

- `distinct()` : discard duplicate elements in the stream
- `filter(predicate)` : discard elements for which the predicate returns false
- `takeWhile(predicate)` : end the stream as soon as the predicate returns false
- `dropWhile(predicate)` : skip all elements until the predicate returns false
- `limit(n)` : end the stream after n elements
- `skip(n)` : skip the first n elements

#### Operations on all elements

- `map(function)` : apply a function to all elements of the stream (can change the stream underlying element type)
- `flatMap(function)` : similar to `map()` but the function returns a stream and `flatMap()` returns a single combined stream (not a stream of streams)
- `peek(consumer)` : execute a function on each element of the stream without changing the stream
- `sorted()` : sort all elements of the stream (can take a comparator, for ex when the underlying class does not implement Comparable)


### Terminal Stream Operations

A stream is only consumed when a terminal operation is executed on it.  
The terminal operation does not return a stream.  
After a terminal operation is called on a stream, the stream is consumed and can no longer be used.

- `allMatch(predicate)` : true if the predicate is true for all elements of the stream
- `noneMatch(predicate)` : true if the predicate is false for all elements of the stream
- `anyMatch(predicate)` : true if the predicate is true for at least one element of the stream
- `findAny(predicate)` : return an optional element for which the predicate is true
- `findFirst(predicate)` : return the optional first element for which the predicate is true
- `toArray()` : create an array with all elements of the stream
- `toList()` : create a list with all elements of the stream
- `count()` : size of the stream
- `max()` : optional max element of the stream
- `min()` : optional min element of the stream
- `sum()` : sum of elements in the stream
- `summaryStatistics()` : statistics object with the count, sum, min, max and average of elements of the stream
- `forEach(function)` : apply a function to elements of the stream
- `reduce(binaryOp)` : reduce the elements in the stream by applying the reduce function to elements 2 by 2
- `collect(collector)` : use a collector in the `Collectors` utility class to return a mutable data structure, for example `Collectors.toList()`

```java
// use a built-in collector to return a mutable set (from the Collectors utility class)
Random random = new Random();
var numbers = Stream.generate(() -> random.nextInt(100))
                    .limit(20)
                    .collect(Collectors.toSet());

// other built-in collector to generate a hashmap of lists, grouping fields by a function
var numbers = Stream.generate(() -> random.nextInt(100))
                    .limit(20)
                    .collect(Collectors.groupingBy(i -> i % 5));

// define a custom collector by providing 3 lambdas :
// - a supplier : Supplier implementation to create the empty result container (could be StringBuilder, a collection...)
// - an accumulator : BiConsumer implementation to specify how to add one element to the result container
// - a combiner : BiConsumer implementation to specify how to merge two partial result containers
// In this example we define a custom collector that stores the stream elements in a tree set (with ordering)
var numbers = Stream.generate(() -> random.nextInt(100))
                    .limit(20)
                    .collect(
                        TreeSet::new,            // supplier
                        TreeSet::add,            // accumulator
                        TreeSet::addAll          // combiner
                    );
```

### Parallel Streams

Java streams can easily be configured to run in parallel with the `parallel()` method.  
This will leverage the multiple cores available to the program to parallelize the work.  
Behind the hood, it uses a fork-join thread pool.

A parallel stream is not always faster than its sequential version.  
The parallelization comes with an additional overhead for thread management, memory management, data source splitting...  

Some operations also do not work with parallel streams, for example operations on sorted input.  
If we sort data in a parallel stream, it will no longer be sorted when merged back together.

A good practice is to use sequential streams by default, at least for development.  
If a section of code needs to be more performant, we can run benchmarks with a parallel stream to evaluate if it makes sense.

```java
IntStream.rangeClosed(1, 100_000_000)
         .parallel()                     // turn the stream into a parallel stream
         .reduce(0, Integer::sum);       // reduce into the sum

// if we reduce by adding an initial non-zero value, it no longer work with aprallel streams !!
// this is because each worker will add the initial value, so it will be included multiple times !
IntStream.rangeClosed(1, 100_000_000)
         .parallel()                     // turn the stream into a parallel stream
         .reduce(5, Integer::sum);       // the value "5" will be added multiple times ! (once for each worker)
```

## Regular Expressions

Regex can be used with strings to search, replace or split on matches.

Useful regex patterns include :
- `\\d` : digit
- `\\w` : letter, digit or underscore
- `\\R` : end of line (both Linux and Windows)
- `\\s` : whitespace (space, tab, new line)
- `\\p{<PROPERTY>}` : match specific built-in properties
  - `\\p{L}` : any letter from any language
  - `\\p{Punct}` : any ASCII punctuation
  - `\\p{Digit}` : same as `\\d`
  - `\\p{Lower}` : same as `[a-z]`
  - `\\p{Upper}` : same as `[A-Z]`
  - `\\p{Alpha}` : same as `[a-zA-Z]`
  - `\\p{Alnum}` : same as `\\w` or `[a-zA-Z0-9_]`
- `.*` : any number of characters (greedy expression : matches as many characters as possible)
- `.*?` : any number of characters (reluctant expression : stops matching as soon as it can)

We can use a **back-reference** in a regex to reference an earlier group of the regex.  
For example the regex `<(h\\d)>.*</\\1>` can match HTML headers with their opening and closing tags.  

### Regex with String

```java
String str = "beautiful";
String regex = "[aiueo]{3,5}";
boolean match = str.matches(regex);                  // false (must be entire match)
boolean match = str.matches(".*" + regex + ".*");    // true

String str = "I have 2 kids, 3 dogs and 11 cats.";
String regex = "[0-9]+";
String replaced = str2.replaceFirst(regex, "X");    // replace first match
String replaced = str2.replaceAll(regex, "X");      // replace all matches
String[] splitted = str2.split(regex);              // split string on matches

String paragraph = """
        This is line 1.
        This is line 2.
        And this is line 3.
        """;
var lines = paragraph.split("\\R");
var words = paragraph.split("\\s");
```

### Regex with Scanner

The `Scanner` uses a regex to specify how it tokenizes its input.  
By default, it splits at every whitespace, so the `next()` method returns each word.  
We can modify this regex to split on lines for example (to mimic the behavior of `nextLine()`).

```java
// search each scanned line for a regex
String regex = "\\d+";
Scanner scanner = new Scanner(paragraph);
while (scanner.hasNext()) {
    System.out.println(scanner.findInLine(regex));    // print first match of the regex in the line
    scanner.nextLine();
}

// change the scanner delimiter regex
Scanner scanner = new Scanner(paragraph);
scanner.useDelimiter("\\R");
while (scanner.hasNext()) {
    System.out.println(scanner.next());    // print each line instead of each word
}
```

### Regex with a Pattern and a Matcher

Java also has a `Pattern` class that allows to compile a regex string into a re-usable pattern.  
That is especially useful if we are using the same regex multiple times.  
It also exposes a lot more regex features than the String class, for example the capture of groups.

A `Matcher` object is instantiated from a pattern and a string to match.  
This object has a state that keeps track of how much it has matched so far.

```java
// use the Pattern.matches() static method for a one-time match, similar to String.matches() 
String regex = "\\d{2}";
String sentence = "I have 12 dogs and 28 cats";
boolean m = Pattern.matches(regex, str);

// define a re-usable Pattern object
Pattern pattern = Pattern.compile(regex);

// split the strings by a pattern as a stream
pattern.splitAsStream(sentence);

Matcher matcher = pattern.matcher(sentence);
boolean m = matcher.matches();  // matches the entire string
matcher.start();                // start index of the match (throw if no match)
matcher.end();                  // end index of the match (throw if no match)

matcher.reset();                // reset the matcher state
matcher.lookingAt();            // match from the start but not necessarily until the end, and uses a reluctant match if specified
matcher.find();                 // match the pattern anywhere in the string (not only at the start like matches() and lookingAt())

// iterate on successive matches with find()
matcher.reset();
while (matcher.find()) {
    System.out.println("Match found between position " + matcher.start() + " and " + matcher.end());
}

// replace one or more matches
Pattern nbPattern = Pattern.compile("\\d{2}");
Matcher nbMatcher = nbPattern.matcher("06 12 34 56 78");
String replacedOne = nbMatcher.replaceFirst("XX");        // XX 12 34 56 78
String replacedAll = nbMatcher.replaceAll("XX");          // XX XX XX XX XX

// group capture
// group 0 always exists when there is a match, it is the entire matched subsequence
// group 1 and later are the groups captured with brackets
Pattern datePattern = Pattern.compile("(\\d{4})/(\\d{2})/(\\d{2})");
Matcher dateMatcher = datePattern.matcher("Birthday: 2024/06/01");
if (dateMatcher.find()) {
    String fullMatch = dateMatcher.group();
    String year = dateMatcher.group(1);
    String month = dateMatcher.group(2);
    String day = dateMatcher.group(3);    
 }
 
 // named group, to access it by name instead of index
Pattern pattern = Pattern.compile("Age : (?<age>\\d+) - Gender : (?<gender>[MF])");
Matcher matcher = pattern.matcher("Name : Bob - Age : 28 - Gender : M");
if (matcher.find()) {
    String age = matcher.group("age");
    String gender = matcher.group("gender");
 }
 
 // get the match results as a stream
String paragraph = """
        "Name : Bob - Age : 28 - Gender : M"
        "Name : Alice - Age : 18 - Gender : F"
        "Name : Jane - Age : 23 - Gender : F"
        """;
Pattern pattern = Pattern.compile("Age : (?<age>\\d+) - Gender : (?<gender>[MF])");
Matcher matcher = pattern.matcher(paragraph);
matcher.results().forEach(match -> {
    System.out.println(match.namedGroups());
    System.out.println(match.group("age"));
    System.out.println(match.group("gender"));
});
```


## Concurrency and Multi-Threading

A **process** (or application) is a unit of execution with its own memory space (heap).  
A process cannot access the heap of another process.

A **thread** is a single unit of execution within a process.  
Every process has at least one thread (the main thread), and can spawn others to parallelize its processing.  
Every thread of a process shares the same heap memory.  
Each thread also has its own stack, for the variables and methods defined during its execution.

The `Thread` class implements the `Runnable` interface, and exposes static methods to access and operate on the current thread :
```java
Thread thread = Thread.currentThread();

thread.getId();
thread.getName();
thread.getPriority();    // 1 to 10, drives how they get scheduled
thread.getState();
thread.getThreadGroup();
thread.isAlive();

thread.setName("my-thread");
thread.setPriority(Thread.MAX_PRIORITY);

Thread.sleep(1000);      // pause the current thread for 1 sec
```

### Thread Creation

There are multiple ways to create a thread :
- extend the `Thread` class and instantiate this subclass
- create a new instance of `Thread` passing it a `Runnable` object (usually a lambda)
- use an executor to create some threads

```java
// Create a subclass of Thread
public class CustomThread extends Thread {
    @Override
    public void run() {
        for (int i = 0; i < 10; i++) {
            System.out.println(i);
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }
}

CustomThread thread = new CustomThread();
thread.run();                                // start the thread synchronously (blocking the main thread, in real code we never call it like this)
thread.start();                              // start the thread asynchronously (not blocking the main thread)


// Create a Runnable instance to construct the Thread
Thread customThread = new Thread(() -> {
        for (int i = 0; i < 10; i++) {
            System.out.println(i);
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                e.printStackTrace();
                Thread.currentThread().interrupt();     // re-interrupt the thread
            }
        }
});
```

### Thread Management

#### Join and Interrupt

```java
CustomThread thread = new CustomThread();
thread.start();

// interrupt a running thread
thread.interrupt();

// waits for a specific threat to complete
try {
    thread.join();
} catch (InterruptedException e) {
    e.printStackTrace();
}

// can do an action depending on if the thread we waited for was interrupted or not
if (thread.isInterrupted()) {
    System.out.println("My custom thread was interrupted.");
} else {
    System.out.println("My custom thread completed.");
}
```

The heap is shared between threads, so objects instantiated in the parents can be shared by multiple threads.  
This can lead to tricky problems, because the order of operations between parallel threads is undefined.  

Thee **Java Memory Model** is a specification of rules and behaviors to follow when working with threads :
- atomicity of operations
- synchronization (control of resource access by threads) 

When multiple threads access the same object or field, Java can optimize the code to provide a copy of the object in each thread.  
This can lead to errors if a thread is expecting a change from another thread on a shared object.  
For this situation, Java introduced the `volatile` modifier for a field, to specify it can be modified by multiple threads.  
This forces Java to read and write it from the main memory instead of a thread-specific cache memory.

#### Synchronize and Intrinsic Lock

The `synchronized` keyword can be used as a modifier of a method.  
Multiple threads cannot execute synchronized methods at the same time on the same instance.

Every object in Java has an intrinsic lock (or monitor lock), that is used by the `synchronized` mechanism.  
When a thread wants to execute a synchronized method for an instance, it takes the intrinsic lock on that instance.  
Other threads have to wait for it to release the lock before they can execute a synchronized method on that same instance.

This makes the synchronized methods body atomic from a thread perspective.

Instead of making an entire method `synchronized`, we can define a `synchronized` block that locks on a specific object.  
Multiple threads can go through the synchronized block at the same time, as long as they process different values of this object.  
We can synchronize on `this` (equivalent of a synchronous method) or any other object, like a specific field of the instance for example.

```java
synchronized (this.name) {
    // act on the name in a thread-safe way
}
```

A lock can only be obtained on an object, not on a primitive type.  
If we want to lock on a primitive type (for example a price field of type double) we can create a dedicated lock object.  
The lock object can be of type `Object` since we only use it for its intrinsic lock.

Note that locks on objects is Java uses **re-entrant synchronization**.  
This means that a thread that already has a lock can enter another synchronized block on the same lock.

The `Object` class also exposes the `wait`, `notify` and `notifyAll` methods to work with locks.  
- `wait()` : release the object lock and go to sleep until it gets awakened by a notify call
- `notify()` : wake up one random thread that is waiting for this lock
- `notifyAll()` : wake up all threads that are waiting for this lock

The `wait()` instruction should always be in a while loop to check if the condition we were waiting for is true.  
It is possible that the thread was awakened for an unrelated reason, so we should not assume that because we are awake the condition is true.

#### Java Lock Interface

The intrinsic lock has some limitations :
- no fairness (any thread can get the lock once released, not necessarily the one that requested it first)
- no way to test if the lock is already taken
- no way to interrupt a blocked thread
- no way to debug by examining the lock state
- exclusive lock (not 2 objects can take it at the same time)

Since Java 5, we can use the `Lock` interface in `java.util.concurrent` package, that exposes the methods :
- `lock()` : obtain the lock (block the thread until it gets the lock)
- `lockInterruptibly()` : similar to `lock()` but allows the thread to be interrupted while waiting
- `tryLock()` : obtain the lock if it is free at time of invocation
- `tryLock(timeout)` : wait up to the given timeout to obtain the lock
- `unlock()` : release the lock (must be called in a `finally` block every time we use a `lock()` or `tryLock()`)

The `ReentrantLock` class is the main implementation of the `Lock` interface.  
It offers the same concurrency as the intrinsic lock, with extended capabilities.

```java
public class ObjectUsingLock {
    Lock lock = new ReentrantLock();
    
    public void doWork() {
        lock.lock();
        try {
            // do something
        } finally {
            lock.unlock();
        }
    }
}
```

The `ReadWriteLock` interface provides a way to allow multiple threads to read as long as no thread is writing.  
It maintains 2 `Lock` objects internally (a read lock and a write lock) that can be accessed with `readLock()` and `writeLock()`.  
Its implementation is the `ReentrantReadWriteLock` class.


### Executor Service

Manual management of the threads using the `Thread` class can be complex and cause scalability issues.  
Java introduced the `ExecutiorService` interface to simplify thread management.  
An executor service uses a thread pool to reduce the cost of thread creation.  
Threads are created in the thread pool at the executor creation, and new tasks queued and picked up by the next available thread.  
It makes efficient use of the multiple cores of the machine to execute the threads in parallel.

An executor takes some `Runnable` or `Callable` tasks to execute, assigns them to a thread and execute them.

Multiple implementations of the `ExecutorService` interface are available in the `Executors` factory :
- `Executors.newSingleThreadExecutor()` : executor with a single thread, so the tasks are done sequentially
- `Executors.newFixedThreadPool(3)` : executor with a fixed number of threads in its pool
- `Executors.newCachedThreadPool()` : executor with a variable number of threads in its pool (grow or shrink with tasks load)
- `Executors.newScheduledThreadPool()` : variation of the cached thread pool with a mechanism to schedule tasks to run at certain time

Main methods of the executor service are :
- `execute(runnable)` : execute a `Runnable` task, it returns no result  
- `submit(callable)` : execute a `Callable` task, it returns a `Future` result
- `invokeAll(callableList)` : execute all `Callable` tasks and return the list of `Future` results
- `invokeAny(callableList)` : execute all `Callable` tasks and return the result (not a `Future`) of one that succeeded
- `shutdown()` : graceful shutdown, continue the execution of on-going tasks but stop accepting new ones
- `shutdownNow()` : brutal shutdown, immediately stops on-going tasks
- `awaitTermination()` : block until the completion of all on-going tasks

We usually don't need to customize the threads used by the executors.  
In case we do (to modify the thread name for example), we can create a class implementing the `ThreadFactory` interface.  
This thread factory object can be provided to the Executors static methods when creating an executor.

```java
// instantiate an executor from the Executors factory
var executor = Executors.newSingleThreadExecutor();

// execute a Runnable
executor.execute(() -> {
    System.out.println("Executing Runnable in thread " + Thread.currentThread().getName());
});

// submit a Callable and get its result
Future<Integer> future = executor.submit(() -> {
    System.out.println("Executing a Callable in thread " + Thread.currentThread().getName());
    return 13;
});

// shutdown the executor (otherwise the program does not stop)
executor.shutdown();
```

Example of scheduled executor :

```java
// instantiate a scheduled executor from the Executors factory
var executor = Executors.newScheduledThreadPool(3);

// schedule a Runnable to execute in 2 seconds
executor.schedule(
    () -> { System.out.println("Executing..."); },
    2,
    TimeUnit.SECONDS
);

// schedule a Runnable to run with a fix interval of 2 seconds between each call, starting in 5 seconds
// we get a handle on the task that can be cancelled to stop the infinite execution schedule
var scheduledTask = executor.scheduleWithFixedDelay(
    () -> { System.out.println("Executing..."); },
    5,                           // initial delay
    2,                           // delay after completion before re-executing the task
    TimeUnit.SECONDS
);

// wait for 10 seconds and cancel the scheduled task
Thread.sleep(10 * 1000);
scheduledTask.cancel();

// we can also schedule a task to run every 2 seconds, no matter how long it takes to run
var scheduledTask = executor.scheduleAtFixedRate(
    () -> { System.out.println("Executing..."); },
    5,                           // initial delay
    2,                           // delay between the start of 2 consecutive execution starts
    TimeUnit.SECONDS
);
```

Common collections (HashMap, HashSet, LinkedList, ArrayList...) are not thread-safe, because they do not have any thread-synchronization mechanism.  
A thread can modify a collection while another one iterates on it, causing inconsistencies.  
To use these collections across thread, we need to perform the synchronization ourselves.

We can make a collection instance thread-safe by using the static synchronized wrapper in the `Collections` class.  
This creates a wrapper that uses a lock on the entire collection for every operation :

```java
Map<Integer, String> hashMap = new HashMap<>();
Map<Integer, String> synchronizedMap = Collections.synchronizedMap(hashMap);
```

Java also has concurrent collections, that are more fine-grain in their locking mechanism and have better performance than the synchronized wrappers : 
- `ConcurrentHashMap`: not sorted
- `ConcurrentSkipListMap`: sorted
- `ConcurrentLinkedQueue`: list for frequent insertion and removal
- `CopyOnWriteArrayList` : for read-heavy workload with rare modification
- `ArrayBlockingQueue` : fixed-size queue that blocks when pulling on empty or offering on full array (designed for FIFO)

Most common problems with multi-threading are :
- `dead-lock` : 2 threads are blocked waiting for each other to release a resource
- `live-lock` : 2 threads are looping infinitely waiting for the other to take action
- `starvation` : a thread is not able to obtain the resources it needs in order to execute


## Database Connection

### Database Installation

Java can interact with most popular database vendors with the same interface.  
It abstracts away the vendor-specific differences, so only the connection string would change from a database vendor to another.  

As an example, we can work with the MySQL community edition.  
The Windows MySQL installer can be downloaded at https://dev.mysql.com/downloads   
Ensure you install the latest MySQL server, MySQL WorkBench (Database GUI), and optionally the MySQL Shell.  
Configure the root password, and create a different user for daily database management.

### JDBC (Java Database Connectivity)

JDBC is the Java way to connect to a wide variety of databases, including relational, NoSQL and object-oriented databases.   
It lies in the `java.sql` package (JDBC core) and `javax.sql` (API for server-side data source access).  
It abstracts the connectivity logic under a single interface.  
JDBC even works with spreadsheets and flat files, allowing to use SQL to interact with the files content.

Each database vendor will provide a **JDBC driver**, which is an implementation of the JDBC API for its specific database.  
This JDBC driver is usually a JAR file that can be downloaded from Maven repository or online (search for "MySQL Connectors" for example).

A JDBC driver allows to :
- connect to the database
- execute SQL queries
- execute stored procedures and functions
- retrieve and process results
- handle database exceptions

#### Connection

First we need to include the JAR of the JDBC driver to the project.  
In IntelliJ, we can simply go to : `Project Structure > Libraries > + > From Maven > mysql`  
It would display the available mysql plugins on Maven repository, for example `com.mysql:mysql-connector-j:8.4.0`  
In a real project, we would need to add this external dependency to the Maven `pom.xml` file or to the Gradle build file.

In code, there are 2 ways to get a connection to a database using JDBC :
- the old way using a `DriverManager` connection with a connection string
- the new way using a `DataSource` connection with either a connection string or all its individual parts

The connection string format is vendor-specific, for example for mysql :
```java
private static final String CONN_STRING = "jdbc:mysql://localhost:3306/music";

// connect using the DriverManager (from java.sql)
// we need a try-with-resource structure to properly end the connection on exit
try (Connection conn = DriverManager.getConnection(CONN_STRING, "user123", "password123")) {
    // we are connected
} catch (SQLException e) {
    throw new RuntimeException(e);
}

// connect using the DataSource (from javax.sql)
var dataSource = new MySqlDataSource();
// dataSource.setURL(CONN_STRING);
dataSource.setServerName("localhost");
dataSource.setPort(3306);
dataSource.setDatabaseName("music");

try (Connection conn = dataSource.getConnection("user123", "password123")) {
    // we are connected
    
    // metadata about the database connection
    DatabaseMetaData metadata = conn.getMetaData();
    
} catch (SQLException e) {
    throw new RuntimeException(e);
}
```

In a real application, the server name, port, database name and credentials are usually loaded from a properties file.  
For more security, we can also consider having the password as an env variable.
```
serverName=localhost
port=3306
databaseName=music
user=user123
password=password123
```

#### JDBC Statement

The `Statement` interface is an interface in JDBC that allows to execute SQL queries in the underlying database.  
The `Statement` object is created from the database connection, and must be closed (for example in a try-with-resource block).  
To ensure compatibility with most database vendors, **ANSI SQL** should be used and vendor-specific SQL (like `LIMIT`) should be avoided.

An SQL query is executed in the database with a method on the Statement object :
- `executeQuery(String)` for a SELECT query, return a `ResultSet` instance containing the selected rows
- `executeUpdate(String)` for DML (Data Manipulation Language) statements like INSERT / UPDATE / DELETE queries, return the number of affected rows
- `execute(String)` can be used with both SELECT or DML queries, and return true if a ResultSet is available (SELECT)

A `ResultSet` also needs to be closed, but it is automatically closed when the `Statement` is closed.  
The `execute()` method is used when we do not know if the query is a SELECT or not, or if the query returns multiple result sets.  
When a result set is available in the statement after query execution, we can access it with the `statement.getResultSet()` method.  
We can also confirm the number of updated rows with the `statement.getUpdatedCount()` method.

```java
try (
    Connection conn = dataSource.getConnection("user123", "password123");
    Statement statement = conn.createStatement();
) {
    String query = "SELECT * FROM music.songs WHERE song_title LIKE '%aki%'";
    ResultSet resultSet = statement.executeQuery(query);
    
    // metadata about the columns of the result (name, type, charset...)
    resultSet.getMetadata();
    
    // iterate over the rows of the result
    while (resultSet.next()) {
          System.out.printf("%d : %s%n",
                  resultSet.getInt("song_id"),                // access int field
                  resultSet.getString("song_title"));         // access String field
    }
} catch (SQLException e) {
    throw new RuntimeException(e);
}
```

A single statement can be used to execute multiple SQL queries.  
We can specify in the `executeUpdate()` method to make the generated keys available for retrieval.  
That is useful when creating a row in a table, and then rows in other tables using its ID as a foreign key.  
```java
// execute an insert query and keep track of generated keys
String query = "INSERT INTO artists(artist_name) VALUES ( 'Celine Dion' )";
statement.executeUpdate(query, Statement.RETURN_GENERATED_KEYS);

// retrieve the generated key if available
ResultSet result = statement.getGeneratedKeys();
int artistId = (result != null && result.next()) ? result.getInt(1) : -1;
```

#### Transactions

By default, JDBC connections have auto-commit enabled, so every change is committed in the database after each query execution.  
To commit multiple queries in a single atomic transaction, we should turn auto-commit off.  
In that case, we must manually call the `conn.commit()` method to commit all changes to the database.

```java
// initialte a transaction
conn.setAutoCommit(false);

try {
    // execute multiple queries in a single transaction
    statement.executeUpdate("DELETE * FROM songs where artist_id = 13");
    statement.executeUpdate("DELETE * FROM artists where artist_id = 13");
    
    // commit the transaction
    conn.commit();
    
} catch (SQLException e) {
    e.printStackTrace();
    conn.rollback();             // rollback in case of failure            
}

// re-enable auto-commit if desired
conn.setAutoCommit(true);
```

#### Batches

The execution of a statement is a resource-intensive and time-consuming operation.  
If we have multiple queries to execute, we can group them into a single batch to call the execution only once.  
This only makes sense for DML queries that modify the content of the database.

```java
// include multiple queries in a batch
statement.addBatch("DELETE * FROM songs where artist_id = 13");
statement.AddBatch("DELETE * FROM artists where artist_id = 13");

// execute the batch and get the number of affected rows for each query
int[] results = statement.executeBatch();
```

#### Prepared Statements

When executed, a statement needs to be parsed and compiled by the database server.  
An execution plan is established to decide how the statement will be executed.  
This operation takes time at every statement execution.

If we use multiple times the same statement, we can use a `PreparedStatement` instance to compile it once and use it multiple times.  
It can contain placeholders for parameters of different types (specified with `?` in the query string).  

Prepared statements also improve security, preventing SQL injection by limiting the impact of parameters.  
Each placeholder can only be replaced by a value of the expected type, so it eliminates the risk of unexpected SQL queries.

```java
// create a PreparedStatement with placeholders in a try-with-resource block
String query = "INSERT INTO songs (artist_id, song_name) VALUES ( ? , ? )";
try (PreparedStatement preparedStatement = conn.prepareStatement(query)) {

    // give values to the placeholders
    ps.setInt(1, 13); 
    ps.setString(2, "Hell Song");
    
    // execute the prepared statement  
    ResultSet resultSet1 = preparedStatement.executeQuery();
    
    // re-use the same prepared statement for another execution
    ps.setInt(1, 14);
    ps.setString(2, "Sk8er Boi");
    ResultSet resultSet2 = preparedStatement.executeQuery();
}
```

#### Callable Statements (Stored Procedures and Stored Functions)

A stored procedure is a sequence of SQL instructions and data manipulation bundled in a reusable module.  
It is a pre-compiled SQL group of queries stored in the database server.

Stored procedures help with application performance, modularity and security.  
For example, the database server can allow Java to execute stored procedures but prevent any other SQL query execution.

The stored procedure must be created in the database server via SQL.  
It supports IN, INOUT and OUT parameters.  

For example, to create an artist and an album for this artist in the database and return a result, we can define this stored procedure :

```sql
DELIMITER //
CREATE PROCEDURE add_album(IN artist_name VARCHAR(255), IN album_name VARCHAR(255), OUT count INT)
BEGIN
    DECLARE my_artist_id INT;

    -- check if the artist exists
    SELECT artist_id INTO my_artist_id FROM artists WHERE artist_name = artist_name;

    -- if the artist doesn't exist, insert it
    IF my_artist_id IS NULL THEN
        INSERT INTO artists (artist_name) VALUES (artist_name);
        SET my_artist_id = LAST_INSERT_ID();
    END IF;

    -- insert the album
    INSERT INTO albums (artist_id, album_name) VALUES (artist_id, album_name);
    
    -- dummy return value
    SET count = 12;
END;
//
DELIMITER ;
```

JDBC supports the execution of stored procedures and the retrieval of their results with the `CallableStatement` class.  
To execute a stored procedure we use a parametrized SQL query using the `CALL` instruction.

```java
String query = "CALL music.add_album( ? , ? , ? )";
CallableStatement callableStatement = conn.prepareCall(query);

// set the value for IN parameters
callableStatement.setString(1, "Avril Lavigne");        // set 1st parameter of the stored procedure (artist_name)
callableStatement.setString(2, "Let Go");               // set 2nd parameter of the stored procedure (album_name)

// register the OUT parameter
callableStatement.registerOutParameter(3, Types.INTEGER);

// execute the CALL statement
callableStatement.execute();

// retrieve the OUT parameter value
int result = callableStatement.getInt(3);
```

**Stored functions** are an alternative to stored procedures defined in the database server.  
They always return a single value, and are designed to have no side effect and to not modify data in the database.  
While stored procedures are used for INSERT/UPDATE/DELETE, stored functions are used for SELECT and JOIN on multiple tables.  
Stored functions can be used directly in an SQL statement (in SELECT, WHERE or JOIN clauses).

In JDBC, calling a stored function is very similar to a stored procedure with a single output parameter :

```java
// use the {} escape sequence to specify to JDBC that we execute a function and not a stored procedure
String query = "{ ? = CALL music.count_album( ? ) }";
CallableStatement callableStatement = conn.prepareCall(query);

// register the function result
callableStatement.registerOutParameter(1, Types.INTEGER);

// set the value for the function parameters
callableStatement.setString(2, "Avril Lavigne");        // set IN parameter of the stored function (artist_name)

// execute the CALL statement
callableStatement.execute();

// retrieve the OUT parameter value
int result = callableStatement.getInt(1);
```

#### SQLException

Most exceptions thrown by the JDBC classes extend the `SQLException` class.  
When caught, it is often useful to react in a certain way for a specific type of exception.  
This logic can be implemented by using the SQL state (vendor-neutral) or the error code (vendor specific).  

```java
try {
    // operations with JDBC
} catch (SQException e) {
    String state = e.getSQLState();
    String errorCode = e.getErrorCode();
    String message = e.getMessage();
}
```

### JPA (Jakarta Persistence API) and ORM (Object-Relational Mapping)

**JPA** is a specification provided by JSE (Java Standard Edition) to manage relational databases in Java.  
Java does not have a default implementation of it, but there external **JPA providers** like **Hibernate**, **Spring JPA** or **EclipseLink**.  

It makes use of the **ORM** (Object-Relational Mapping) technique to associate a Java object with a row in a database.  
With JPA, we can interact with the database without writing any SQL code, only by using Java objects.

JPA can be seen as an abstraction layer between the application code and JDBC that applies the SQL queries in the database.  
JPA simplifies the code and database operations, and makes the code more portable across different database systems.

A JPA **entity** is a class that represents a table in a relational database.  
JPA uses annotations in the Java code to specify the underlying database table structure like `@Entity`, `@Column`, `@Id`, `@OneToMany` ...

The `EntityManager` interface exposes methods to interact with the database :
- `persist()` : make a detached instance managed by the entity manager and persistent (saved in the database)
- `find()` : search for a row with the specified primary key and return a persistent and managed entity
- `merge()` : update  a managed entity (changes are propagated to the database on commit)
- `delete()` : delete the entity instance from management and delete the row from the database

#### Hibernate Setup

To use Hibernate (or any other JPA provider), we need the JDBC, the JPA core lib and the JPA provider classes.  
As done previously, the JDBC is available in the Maven library `com.mysql:mysql-connector-j:8.4.0`.  
Hibernate contains is bundled together with the JPA classes in the Maven library `org.hibernate.orm:hibernate-core:6.5.2.Final`

We then need a Hibernate configuration file under `META-INF/persistence.xml` with the `<persistence>` tag.  
It specifies the driver, database URL, user and password to use to access the underlying database.  
The `META-INF` folder must be part of the classpath of the Java program, under the `src` directory.

```xml
 <persistence xmlns="http://java.sun.com/xml/ns/persistence"
             xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
             xsi:schemaLocation="http://java.sun.com/xml/ns/persistence http://java.sun.com/xml/ns/persistence/persistence_2_0.xsd"
             version="2.0">

    <persistence-unit name="dev.lpa.music">

        <properties>
            <property name="jakarta.persistence.jdbc.driver"   value="com.mysql.cj.jdbc.Driver" />
            <property name="jakarta.persistence.jdbc.url"      value="jdbc:mysql://localhost:3306/music" />
            <property name="jakarta.persistence.jdbc.user"     value="demo" />
            <property name="jakarta.persistence.jdbc.password" value="demo" />

            <property name="hibernate.show_sql" value="true" />

        </properties>

    </persistence-unit>
</persistence>
```

#### Hibernate Entity

An entity is a POJO class with annotations for the table and fields.  
We can create one entity for each database table that needs to be represented in Java.

```java
@Entity
@Table(name = "artists")
public class Artist {

    // primary key
    @Id
    @Column(name = "artist_id")
    private int artistId;

    // simple column
    @Column(name = "artist_name")
    private String artistName;

    // contructors (empty one required) + getters + setters
    [ ... ]
}
```

An `EntityManager` is an engine that maps the Java entity instances and the database rows.  
It is the wrapper above JDBC that makes it possible to use entity instances instead of SQL code.  

An entity instance obtained from the entity manager with `entityManager.fetch()` is in managed state.  
It means that any change made to it (with setters) will be saved to the database in the next `entityManager.commit()` call.

An entity instance created with the constructor is in detached state (not managed by the entity manager).  
To make it managed, it needs to be either inserted to the database with `entityManager.persist(entity)` or updated with `entityManager.merge(entity)`.

```java
    // load the persistence.xml file from the classpath and extract a specific persistence unit details
    try (var sessionFactory = Persistence.createEntityManagerFactory("dev.lpa.music");
         EntityManager entityManager = sessionFactory.createEntityManager()
    ) {
        // start a transaction
        var transaction = entityManager.getTransaction();
        transaction.begin();

        // save a new entity in the database
        entityManager.persist(new Artist("Sonata Arctica"));

        // get a row from the database by ID as a Java entity
        Artist artist = entityManager.find(Artist.class, 150);

        // modifying the managed Java entity automatically updates the database on commit
        artist.setArtistName("Stratovarius");

        // delete an entity from the database
        entityManager.remove(artist);

        // commit the changes in the database
        transaction.commit();

    } catch (Exception e) {
        // handle exception
    }
```

#### Tables Relationship

Relationships between tables is handled by Hibernate by Java annotation.  
For example, if an `album` table has an `artist_id` foreign key referencing the `artist` table, we can create an `Album` entity, and add in the `Artist` entity :

```java
@OneToMany(cascade = CascadeType.ALL, orphanRemove = true)
@JoinColumn(name="artist_id")
private List<Album> albums = new ArrayList<>();

public List<Album> getAlbums() {
    return albums;
}

// method in the Artists entity to create an Album entity linked to it by the foreign key
public addAlbum(String albumName) {
    albums.add(new Album(albumName));
}
```

#### JPA Queries

JPA allows to build database queries from code using JPQL (Jakarta Persistence Query Language) that will build the corresponding SQL query.  
JPQL looks a lot like SQL, but applies on entity classes instead of database tables :

```java
// select all entity instances in the Artist entity
String jpql = "SELECT a FROM Artist a";
var query = entityManager.createQuery(jpql, Artist.class);
List<Artist> result = query.getResultList();

// select entity instances in the Artist entity matching a filter with a name parameter
String jpql = "SELECT a FROM Artist a WHERE a.artistName LIKE :nameParam";
var query = entityManager.createQuery(jpql, Artist.class);
query.setParameter("nameParam", "%tra%");
List<Artist> result = query.getResultList();

// similar but using numbered parameters
String jpql = "SELECT a FROM Artist a WHERE a.artistName LIKE ?1";
var query = entityManager.createQuery(jpql, Artist.class);
query.setParameter(1, "%tra%");
List<Artist> result = query.getResultList();

// select one specific field of an entity
String jpql = "SELECT a.artistName FROM Artist a";
var query = entityManager.createQuery(jpql, String.class);
List<String> result = query.getResultList();

// select multiple specific fields of an entity
String jpql = "SELECT a.artistId, a.artistName FROM Artist a";
var query = entityManager.createQuery(jpql, Tuple.class);
List<Tuple> result = query.getResultList();
```

We can also build a JPA query using the `CriteriaBuilder` instead of a raw string.    
It lets us create `CriteriaQuery` instances with a builder pattern.

```java
CriteriaBuilder criteriaBuilder = entityManager.getCriteriaBuilder();
CriteriaQuery<Artist> criteriaQuery = criteriaBuilder.createQuery(Artist.class);
Root<Artist> root = criteriaQuery.from(Artist.class);
criteriaQuery.select(root)
             .where(criteriaBuilder.like(root.get("artistName"), "%eta%"))
             .orderBy(criteriaBuilder.asc(root.get("artistName")));   // add a ORDER BY clause
var query = entityManager.createQuery(criteriaQuery);
List<Artist> result = query.getResultList();
```

It is also possible to execute native SQL queries in the database with Hibernate, with optional placeholders :
```java
String sql = "SELECT * FROM artists WHERE artist_name LIKE ?1 ORDER BY artist_name ASC";
var query = entityManager.createNativeQuery(sql, Artist.class);
query.setParameter(1, "%eta%");
List<Artist> result = query.getResultList();
```


## Java Networking

Networking is used in application development for multiple purposes :  
- data communication in real time between the user and the application
- distributed systems, with an application deployed across multiple servers
- cloud computing
- remote access and control to distributed systems
- inter-applications communication with APIs and Web services

The Java packages used for networking are :  
- `java.net` with low-level APIs (Socket, InetAddress...) and high-level APIs (URL, URI, URLConnection...)
- `java.net.http` (since Java 11) with high-level APIs (HttpClient, WebSocket)
- `java.nio.channels` with the channel API (ServerSocketChannel, SocketChannel, DatagramChannel...)

### Basic Client-Server Socket Communication

We can create a basic server that listens to a port for a client connection, accepts it, reads input from it and sends output.

```java
// create a ServerSocket to listen on a port
try (ServerSocket serverSocket = new ServerSocket(5588)) {

    // block until a connection is established with a client on the listening port
    try (Socket socket = serverSocket.accept()) {

        BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        PrintWriter writer = new PrintWriter(socket.getOutputStream(), true);

        // read input from the socket and send response back
        while (true) {
            String received = reader.readLine();
            if (received.equals("exit")) {
                break;
            }
            writer.println("Processed input : " + received);
        }
    }
} catch (IOException e) {
    throw new RuntimeException(e);
}
```

On the client side, we can create a `Socket` instance to connect to the server, and send and receive data through it :

```java
// create a client socket to connect to the server
try (Socket socket = new Socket("localhost", 5588)) {

    BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
    PrintWriter writer = new PrintWriter(socket.getOutputStream(), true);

    writer.println("Line 1");
    writer.println("Line 2");
    writer.println("exit");

    System.out.println(reader.readLine());   // Processed input : Line 1
    System.out.println(reader.readLine());   // Processed input : Line 2
    System.out.println(reader.readLine());   // null

} catch (IOException e) {
    throw new RuntimeException(e);
}
```

The above server processes only a single incoming connection.  
A common server structure is to use an infinite loop waiting for incoming connections.  
When a client connection is established, the server instantiates a new thread and delegates the work to it.  
This can be done with an `ExecutorService` that submits a task for every incoming connection.  

```java
public static void main(String[] args) {

    // create a ServerSocket to listen on a port
    try (ExecutorService executorService = Executors.newCachedThreadPool();
         ServerSocket serverSocket = new ServerSocket(5588)) {

        while (true) {
            // block until a connection is established with a client on the listening port
            Socket socket = serverSocket.accept();
            // submit a task to the executor to handle the request
            executorService.submit(() -> {
                handleRequest(socket);
            });
        }
    } catch (IOException e) {
        throw new RuntimeException(e);
    }
}

public static void handleRequest(Socket socket) {
    // the handle function is in charge of closing the socket
    try (socket;
         BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        PrintWriter writer = new PrintWriter(socket.getOutputStream(), true)
    ) {
       while (true) {
            String str = reader.readLine();
            if (str.equals("exit")) { break; }
            writer.println("Received: " + str);
        }
    } catch (IOException e) {
        throw new RuntimeException(e);
    }
```

### Socket Channels

`ServerSocket` uses blocking I/O with the `accept()` method.  
This is fine for low volumes of connections, but is not scalable because it requires one thread per client connection.  
A more recent approach in the `java.nio.channels` package is `ServerSocketChannel`, that uses NIO (non-blocking I/O).  
It is a more complex API, but is preferable for applications with numerous concurrent connections requiring low-latency.

A channel represents an open connection to an entity capable of input and output (file, hardware device, network socket, ...).  
A channel is created when calling the static `open()` method on a specific channel implementation.

#### NIO Buffers

A `Buffer` in `java.nio` is a data container for temporary storage.  
A buffer has a state (ready to read, ready to write, empty, full).  
It is more memory-efficient than a simple array.  
There is a buffer subtype for each primitive type (except boolean), for example `ByteBuffer`.  
A buffer can be both readable or writable, and its state is changed from one to the other with the `buffer.flip()` method.

```java
ByteBuffer buffer = ByteBuffer.allocate(1024);   // set the immutable capacity

buffer.put("Hello World".getBytes());   // write to the buffer

buffer.capacity();        // 1024 (immutable)
buffer.limit();           // 1024
buffer.position();        // 11 (position of the write cursor in the buffer)
buffer.remaining();       // 1013 (number of bytes still available in the buffer)

buffer.flip();            // make the buffer readable (instead of writable)

buffer.capacity();        // 1024 (immutable)
buffer.limit();           // 11 (in read mode, the limit is set to the number of bytes available for read)
buffer.position();        // 0 (position of the read cursor in the buffer)
buffer.remaining();       // 11 (number of bytes still available in the buffer)

// read a bytes array from the buffer and convert it to a string 
byte[] byteArr = new byte[buffer.limit()];
buffer.get(byteArr);
System.out.println(new String(byteArr, StandardCharsets.UTF_8));

```

Channels use buffers for data transfer :  
- the `read()` method takes a buffer as input and fills this buffer with data from the connected entity (accessed with `buffer.get()`)
- the `write()` method takes a buffer as input (populated with `buffer.put()`) and transfered the buffered data to the connected entity

#### ServerSocketChannel

We can update the server code to use `ServerSocketChannel` instead of `ServerSocket`.  
We then need to bind the socket of the created channel to the port to listen to.  
We can configure the channels (server and client) to be non-blocking.  
With this setup, we can keep track of all client connections, and loop through all of them infinitely.

```java
public static void main(String[] args) {

    // create a server socket channel
    try (ServerSocketChannel serverChannel = ServerSocketChannel.open()) {
        // bind the socket of the channel to the port to listen to
        serverChannel.socket().bind(new InetSocketAddress(5588));
        // configure the server channel so its accept() method no longer blocks
        serverChannel.configureBlocking(false);
        // maintain a list of all ongoing client connections
        List<SocketChannel> clientChannels = new ArrayList<>();

        while (true) {
            // accept a connection made to this channel's socket if any
            SocketChannel clientChannel = serverChannel.accept();
            if (clientChannel != null) {
                // configure the client channel so the read() method does not block
                clientChannel.configureBlocking(false);
                clientChannels.add(clientChannel);
            }

            // read the input received from the client on the channel into a Buffer
            ByteBuffer buffer = ByteBuffer.allocate(1024);

            // for each open client connection, read from it if available
            for (int i = 0; i < clientChannels.size(); i++) {
                SocketChannel channel = clientChannels.get(i);
                int readBytes = channel.read(buffer);
                if (readBytes > 0) {
                    // change to read mode, so the position and limit are set to read from it
                    buffer.flip();
                    // send a response to the client channel
                    channel.write(ByteBuffer.wrap("Processed : ".getBytes()));
                    while (buffer.hasRemaining()) {
                        channel.write(buffer);
                    }
                    // clear the buffer to make it usable by the next client connection
                    buffer.clear();
                } else if (readBytes == -1) {
                    System.out.println("Connection with client closed");
                    channel.close();
                    clientChannels.remove(i);
                }
            }
        }
    } catch (IOException e) {
        throw new RuntimeException(e);
    }
}
```

In the above code, we use a **polling** strategy by calling the non-blocking version of `serverChannel.accept()` and `channel.read()` in an infinite while loop.  
Channels also support an **event-driven** strategy that avoids to actively loop when there is no activity.  
This is implemented by the `SelectableChannel` class, that both `ServerSocketChannel` and `SocketChannel` extend.  
Using a `Selector`, a channel can register to a specific type of events, and execute a callback when the event occurs.

```java
// create a server socket channel
try (ServerSocketChannel serverChannel = ServerSocketChannel.open()) {
    // bind the socket of the channel to the port to listen to
    serverChannel.socket().bind(new InetSocketAddress(5588));
    // configure the server channel so its accept() method no longer blocks
    serverChannel.configureBlocking(false);
    // create a selector that contains all events triggered
    Selector selector = Selector.open();
    // register the server channel for the ACCEPT event
    serverChannel.register(selector, SelectionKey.OP_ACCEPT);

    while (true) {
        // blocking operation waiting for any event to occur
        selector.select();
        Set<SelectionKey> selectionKeys = selector.selectedKeys();
        Iterator<SelectionKey> iterator = selectionKeys.iterator();

        // loop on all events that occurred
        while (iterator.hasNext()) {
            SelectionKey key = iterator.next();
            iterator.remove();

            if (key.isAcceptable()) {
                // handle ACCEPT event : a client wants to connect
                SocketChannel clientChannel = serverChannel.accept();
                clientChannel.configureBlocking(false);
                // register the client channel for the READ event
                clientChannel.register(selector, SelectionKey.OP_READ);
            } else if (key.isReadable()) {
                // handle READ event : data is available on a client channel
                SocketChannel clientChannel = (SocketChannel) key.channel();
                // read data in a byte buffer
                ByteBuffer buffer = ByteBuffer.allocate(1024);
                int byteRead = clientChannel.read(buffer);
                // process this byte buffer
                if (byteRead > 0) {
                    buffer.flip();      // flip to read mode
                    byte[] data = new byte[buffer.remaining()];
                    buffer.get(data);
                    String message = "Processed : " + new String(data);
                    clientChannel.write(ByteBuffer.wrap(message.getBytes()));
                } else if (byteRead == -1) {
                    // end of connection
                    key.cancel();
                    clientChannel.close();
                }
            }
        }
    }
} catch (IOException e) {
    throw new RuntimeException(e);
}
```

We can also use a UDP version of the sockets and channels.  
In that case, there is no connection (so no `accept()` method), we just send and receive datagram packets.  
The data is sent as `DatagramPacket` in UDP, instead of `InputStream` and `OutputStream` in TCP.  
Therefore, the destination of a packet is no longer included in the connection but in each packet itself.

```java
// server side
try (DatagramSocket serverSocket = new DatagramSocket(5588)) {
    byte[] byteArray = new byte[1024];
    DatagramPacket clientPacket = new DatagraPacket(byteArray, byteArray.length);  // wrapper on a byte array
    serverSocket.receive(clientPacket);
    String receivedMessage = new String(byteArray, clientPacket.getLength());
}

// client side
try (DatagramSocket clientSocket = new DatagramSocket()) {
    byte[] byteArray = "Hello World".getBytes();
    DatagramPacket clientPacket = new DatagraPacket(       // wrapper on a byte array
            byteArray, byteArray.length,
            InetAddress.getLocalHost(), 5588);             // destination of the datagram  
    clientSocket.send(clientPacket);
}
```

### High-level Networking

The `URI` class represents a resource of any kind by location or by name (email address, webpage, relative file path...).

The `URL` class represents a specific type of URI for resources in the world wide web.  
We can create a `URL` that does not actually reference an existing object, it would only fail when we try to access it.

It is common when we work with a website to define :  
- a base URI that contains the host, port and domain that is a valid URL
- some relative URIs from the base URI to access various pages and resources on the website  

In that case, when the website location changes, only the base URI needs to be updated.

```java
URI uri = URI.create("http://user123:pwd123@host123:5588/api/products?type=1#free");

uri.getScheme();        // http
uri.getUserInfo();      // user123:pwd123
uri.getHost();          // host123
uri.getPort();          // 5588
uri.getPath();          // api/products
uri.getQuery();         // type=1
uri.getFragment();      // free

uri.toURL();            // convert a URI into a URL (throw if not a valid URL)

// resolve a URI from a base and a relative URI
URI uriBase = URI.create("http://www.example.com");
URI uriRelative = URI.create("api/products");
URI uriCombined = uriBase.resolve(uriRelative);

// read a web URL content as a stream
InputStream urlStream = url.openStream();
try (BufferedReader reader = new BufferedReader(new InputStreamReader(urlStream))) {
    String line;
    while ((line = reader.readLine()) != null) {
        System.out.println(line);
    }
}

// open a connection manually without the openStream() shortcut to allow customization of the connection
URLConnection connection = url.openConnection();
connection.getContentType();        // content type + charset
connection.getHeaderFields();       // HTTP headers
connection.connect();               // actually connects to the remote URL
connection.getInputStream();        // return the same input stream as url.openStream()

// use a HttpURLConnection instead of a URLConnection to use HTTP-specific methods
HttpURLConnection connection = (HttpURLConnection) url.openConnection();
connection.setRequestMethod("GET");
connection.setRequestProperty("User-Agent", "Firefox");     // custom header
connection.setReadTimeout(5000);
connection.getResponseCode();          // call the connect() method to get the response code
connection.getResponseMessage();
```

### HTTP server

HTTP traffic is the most common in modern networking, so Java 11 introduced `HttpServer` to simplify HTTP networking.  
This should be preferred over lower-level `Socket` and `Channel` classes for HTTP-only traffic.

We define a `HttpContext` that maps the queried URIs to the handlers to execute for each URI.

```java
// HTTP Server
HttpServer server = HttpServer.create(new InetSocketAddress(5588), 0);
server.createContext("/", httpExchange -> {
    String method = httpExchange.getRequestMethod();
    URI uri = httpExchange.getRequestURI();
    String body = new String(httpExchange.getRequestBody().readAllBytes());  // useful for POST queries
    byte[] bytes = "<html><body><h1>TEST<h1></body></html>".getBytes();      // response content
    httpExchange.sendResponseHeaders(HTTP_OK, bytes.length);
    httpExchange.getResponseBody().write(bytes);
    httpExchange.close();
});
server.start();

// Client side, use a HttpURLConnection to make it a POST request with a custom body
URL url = URI.create("http://localhost:5588/").toURL();
HttpURLConnection conn = (HttpURLConnection) url.openConnection();
conn.setRequestMethod("POST");
conn.setDoOutput(true);         // required to include a body in a POST request
conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
String body = "name=Bob&age=23";
conn.setRequestProperty("Content-Length", String.valueOf(body.getBytes().length));
DataOutputStream outputStream = new DataOutputStream(conn.getOutputStream());
outputStream.writeBytes(body);
outputStream.flush();
outputStream.close();
```

Instead of `HttpURLConnection`, Java 11 introduced `HttpClient` that makes the client-side more user-friendly.  
`HttpClient` also supports HTTP 2, which `HttpURLConnection` does not.

```java
HttpClient client = HttpClient.newHttpClient();
HttpRequest request = HttpRequest.newBuilder()
        .POST(HttpRequest.BodyPublishers.ofString("name=Bob&age=23"))
        .uri(URI.create("http://localhost:5588/"))
        .header("User-Agent", "Chrome")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .timeout(Duration.ofSeconds(30))
        .build();
HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
System.out.println(response.statusCode());
System.out.println(response.headers());
System.out.println(response.body());
```

The `HttpClient` can use `sendAsync()` instead of `send()` to return a `CompletableFuture` that gets completed asynchronously. 

### WebSocket

With the client-server architecture, only the client can initiate the communication, and the server responds.  
If the client is waiting for a result to be available on the server, it needs to regularly sends a request to check if it is ready.  
Websocket is an alternative to the client-server architecture allowing bi-directional communication.  
This is a better design for chats or collaborative tools where the server needs to push data to the client.

The Websocket protocol requires a special handshake when the connection is established.  
When a client connects to the server, it sends a GET request to upgrade the connection from HTTP to WebSocket.  

Java has a `WebSocket` class in the `java.net.http` package that implements a WebSocket on client-side.  
This means that we can create a WebSocket client with native Java only.

To implement a WebSocket server, we can use the external library `org.java_websocket` available on Maven Repository.  
It exposes the `WebSocketServer` class that can be extended to create a custom WebSocket server.  
Its methods take a `WebSocket` object as parameter, but it is a class from the `org.java_websocket` package (not the same as client-side).  

For example, we can create a WebSocket server to implement a simple chat application.  
It accepts client connections, gets the name of each connected client, and broadcasts its messages to other clients.

```java
// Web Server implementation extending the WebSocketServer class from the org.java_websocket library
static class MyWebSocketServer extends WebSocketServer {

    Map<String, String> myConnectedUsers = new HashMap<>();

    public MyWebSocketServer() {
        super(new InetSocketAddress(5588));
    }

    @Override
    public void onOpen(WebSocket webSocket, ClientHandshake clientHandshake) {
        System.out.println("onOpen" + webSocket.getRemoteSocketAddress());
        String name = webSocket.getResourceDescriptor().split("=")[1];
        myConnectedUsers.put(webSocket.getRemoteSocketAddress().toString(), name);
        broadcastToOthers(webSocket, name + " joined the chat.");
    }

    @Override
    public void onClose(WebSocket webSocket, int i, String s, boolean b) {
        System.out.println("onClose " + webSocket.getRemoteSocketAddress());
    }

    @Override
    public void onMessage(WebSocket webSocket, String s) {
        System.out.println("onMessage " + webSocket.getRemoteSocketAddress() + " : " + s);
        String currentUserName = myConnectedUsers.get(webSocket.getRemoteSocketAddress().toString());
        broadcastToOthers(webSocket, "%s : %s".formatted(currentUserName, s));
    }

    @Override
    public void onError(WebSocket webSocket, Exception e) {
        System.out.println("onError " + e.getMessage());
    }

    @Override
    public void onStart() {
        System.out.println("onStart");
    }

    public void broadcastToOthers(WebSocket webSocket, String message) {
        var connections = new ArrayList<>(getConnections());
        connections.remove(webSocket);
        System.out.println("WIll broadcast : " + message);
        broadcast(message, connections);
    }
}

public static void main(String[] args) {
    MyWebSocketServer server = new MyWebSocketServer();
    server.start();
}
```

The WebSocket client does not need the `org.java_websocket` library, it only uses the built-in `WebSocket` class in `java.net.http` package.  
It creates a websocket from the `HttpClient` class with a custom listener implementing the `onText()` method to react when a message is received.

```java
public static void main(String[] args) throws URISyntaxException, ExecutionException, InterruptedException {
    // get user name
    Scanner scanner = new Scanner(System.in);
    System.out.print("Name : ");
    String name = scanner.nextLine();
    // create a websocket
    URI uri = new URI("ws://localhost:5588?name=%s".formatted(name));
    HttpClient client = HttpClient.newHttpClient();
    WebSocket webSocket = client.newWebSocketBuilder()
            .buildAsync(uri, new WebSocket.Listener() {
                @Override
                public CompletionStage<?> onText(WebSocket webSocket, CharSequence data, boolean last) {
                    // print the received message in the chat
                    System.out.println(data);
                    return WebSocket.Listener.super.onText(webSocket, data, last);
                }
            })
            .join();  // wait for the websocket to be ready
            
    // start a chat and write to the websocket when the user writes a line
    while (true) {
        String input = scanner.nextLine();
        if (input .equalsIgnoreCase("exit")) {
            webSocket.sendClose(WebSocket.NORMAL_CLOSURE, "User %s left".formatted(name))
                     .get();    // wait for close to be completed
            break;
        } else {
            webSocket.sendText(input, true);
        }
    }
}
```


## JUnit

JUnit (version 5 at the moment) is the most popular unit-test framework for Java.  
It is integrated in IntelliJ, so we can Alt-Enter on a class name and create a JUnit test class for it.  
It allows to perform some automated tests against our code and throw a `AssertionFailedError` when values are not as expected. 

The test class contains test methods decorated with the `@Test` JUnit annotation.  

Junit exposes several assertion functions like `assertTrue()`, `assertEquals()`, `assertArrayEquals()` ...

```java
class AnimalTest {

    Animal bill;

    @org.junit.jupiter.api.BeforeEach
    void setupEach() {
        bill = new Animal("dog", "Bill", 7);
    }

    @org.junit.jupiter.api.Test
    void getAge() {
        assertEquals(7, bill.getAge(), "Check age field");
        assertNotEquals(8, bill.getAge());
        assertTrue(bill.getAge() > 0, "Age must be positive");
        assertFalse(bill.getAge() < 0);
    }
    
    @org.junit.jupiter.api.Test
    void otherTest() {
        int[] a1 = { 1, 2, 3 };
        int[] a2 = { 1, 2, 3 };
        assertArrayEquals(a1, a2);  // assert elements equality instead of address equality
        assertNull(null);
        assertNotNull(bill);
    }    

    @org.junit.jupiter.api.Test
    void futureTest() {
        fail("Test not implemented yet");
    }    
}
```

The `assertThrows()` method can check if a method throws a specific exception, and returns the exception object for further testing :
```java
@org.junit.jupiter.api.Test
void getName() {
    var e = assertThrows(NullPointerException.class, () -> {
        Animal bob = null;
        bob.getName();
    });
    assertTrue(e.getMessage().contains("\"bob\" is null"));
}
```

We can create a parametrized test, so JUnit runs it once per value in the parametrized list :
```java
@ParameterizedTest
@ValueSource(strings = {"", "A", "AAA", "!!"})
void rename(String name) {
    System.out.println("Test for name = " + name);
    Animal animal = new Animal("dog", name, 12);
    assertEquals(name, animal.getName());
}
```

To define methods to run once before/after each/every tests, we can use the `@BeforeAll`, `@BeforeEach`, `@AfterAll` and `@AfterEach` annotations :
```java
@org.junit.jupiter.api.BeforeAll
static void setupAll() {
    System.out.println("setupAll");
}

@org.junit.jupiter.api.BeforeEach
void setupEach() {
    System.out.println("setupEach");
}

@org.junit.jupiter.api.AfterAll
static void teardownAll() {
    System.out.println("teardownAll");
}

@org.junit.jupiter.api.AfterEach
void teardownEach() {
    System.out.println("teardownEach");
}
```

## Java Modules

Java 9 introduced modules with the **Java Platform Module System** (JPMS), result of Project Jigsaw.  
Modules let developers organize their code and resources more efficiently, and manage dependencies between packages better.  

A module is a higher level of aggregation above Java packages.  
A module is a group of related packages amd resources (images, config files...) along with a module descriptor file.  
Each module contains the resources it uses, instead of having these resources in a resource folder common to the entire project.

There are 4 types of modules :
- **system modules** : Java SE and JDK modules, listed by `java --list-modules`, for example `java.sql`
- **application modules** : custom named modules, defined in the assembled JAR in the `module-info.class` file
- **automatic modules** : unofficial modules included by adding a JAR file to the module path (module named derived from the JAR name)
- **unnamed module** : contain all JAR files loaded in the classpath but not in the module path (for backward compatibility)

There can be only one module in a JAR file, so each module has its own JAR file.

Some packages inside a module can be internal, and others can be exported by the module.  
By default, only the exported packages can be accessed at compile-time and runtime by external modules.  
A module can be `open` so only exported packages are accessible at compile-time but all packages are accessible at runtime (by reflection).  

Each module has a module descriptor file called **module-info.java** at the module root folder.  
It contains the module name and metadata about the module (dependencies, exported packages, reflection permissions).

Metadata in the module file descriptor can be any of the following directives :
- `requires MODULE_NAME` : defines a module required for the current module to work
  - `requires static MODULE_NAME` : optional compile-time only dependency
  - `requires transitive MODULE_NAME` : make all users of our module require this module too 
- `exports PACKAGE_NAME` : expose all public members of a package to users of our module
  - `exports PACKAGE_NAME to PACKAGE_NAME` : expose all public members of a package to a specific package only
- `opens PACKAGE_NAME` : make a specific package open at runtime for reflection
  - `opens PACKAGE_NAME to MODULE_NAME` : make it open at runtime for reflection only to a specific module
- `provides INTERFACE_NAME with CLASS_NAME` : defines service implementations provided by the current module
- `uses INTERFACE_NAME` : defines the services that the current module consumes, allowing to load the right implementation with `ServiceLoader`

IntelliJ has integration with Java modules, we can create one with : `File > New > Module`  
We can call the module `com.myapp.core` for example, and IntelliJ creates the module with a `src` folder in it.  
In this src folder, we can create the package hierarchy, for example packages `com.myapp.core.mypkg1` and `com.myapp.core.mypkg2`.  
We can create the `module-info.java` file at the root of the module, for example : 
```java
module com.myapp.core {
    requires javafx.base;
    requires javafx.controls;
    requires javafx.graphics;
    requires javafx.fxml;
    requires java.sql;
    
    exports com.myapp.core.mypkg1 to javafx.graphics, javafx.fxml;
    opens com.myapp.core.mypkg1 to javafx.fxml;
}
```


## Building Java Projects

## Manual 

- compile the `.java` files into `.class` in the `./build/classes` folder for the JVM to interpret :
```shell
javac -d build/classes src/com/example/*.java
```

- Create a MANIFEST file under `./src` that specifies the main class of the Java application :
```
Main-Class: com.example.MainClass
```

- Generate the JAR file with the `.class` files and the MANIFEST file :
```shell
cd build/classes/
jar cfm hello.jar ../../src/MANIFEST ./com/example/*.class
jar -tf hello.jar             # check the JAR content
```

- Execute the JAR file to run the application :
```shell
java -jar build/jar/hello.jar
```

### Apache Ant

Apache Ant is a Java-based build automation tool, mostly used for Java development.  
It was developed in 2000 as a platform-independent alternative to CMake.  
It is no longer used for new Java projects, but is still widely used for legacy projects.  

Ant allows the automation of the build with a `build.xml` file describing the build steps to run.  
This XML configuration file describes the shell commands required for the build.

To compile a basic Java project with a single Java file `src/com/example/Hello.java`, we can create the following `build.xml` :

```xml
<project name="hello" default="run" basedir=".">
    <!-- Clean target -->
    <target name="clean">
        <delete dir="build"/>
    </target>

    <!-- Compile target -->
    <target name="compile" depends="clean">
        <mkdir dir="build/classes"/>
        <javac srcdir="src" destdir="build/classes"/>
    </target>

    <!-- Jar target -->
    <target name="jar" depends="compile">
        <mkdir dir="build/jar"/>
        <jar destfile="build/jar/hello.jar" basedir="build/classes">
            <manifest>
                <attribute name="Main-Class" value="com.example.Hello"/>
            </manifest>
        </jar>
    </target>

    <!-- Run target -->
    <target name="run" depends="jar">
        <java jar="build/jar/hello.jar" fork="true"/>
    </target>
</project>
```

It defines the 4 following targets : `clean`, `compile`, `jar` and `run`.  
Each one has a dependency on the previous one.  
Each target has a specific XML child tag for each command it needs to run.  

We can then perform each step by calling the Ant CLI :
```shell
ant clean
and compile
ant jar
ant run
```

### Maven

Maven is a tool that was designed as a successor of Ant to build Java programs.  
It offers built-in support for dependency management.  
It enforces a standard project structure so all projects follow the same conventions.  
It has a lot of plugins that can be used to enrich the capabilities of the build.  

To create a basic Maven project, we add the `Hello.java` file under `<PROJECT_ROOT>/src/main/java/com/example/`.  
Then we create a `pom.xml` file (Project Object Model) in the project root : 

```xml
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>Hello</artifactId>
    <version>1.0-SNAPSHOT</version>
    <build>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-compiler-plugin</artifactId>
                <version>3.8.1</version>
                <configuration>
                    <source>11</source>
                    <target>11</target>
                </configuration>
            </plugin>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-jar-plugin</artifactId>
                <version>3.1.0</version>
                <configuration>
                    <archive>
                        <manifest>
                            <mainClass>com.example.Hello</mainClass>
                        </manifest>
                    </archive>
                </configuration>
            </plugin>
        </plugins>
    </build>
</project>
```

We can then build the project and run the program with :
```shell
mvn clean
mvn package
java -jar target/Hello-1.0-SNAPSHOT.jar
```


### Gradle 

Gradle is a modern build tool mostly used to build Java projects, allowing to define tasks in Groovy.  
It relies on a project structure by default, that can be initialized with `gradle init`.   

It does create : 
- a `settings.gradle` Groovy file containing the project name
- the `gradlew` and `gradlew.bat` files for the Gradle wrapper
- the `app/build.gradle` file defining the build tasks (using the `application` plugin for Java projects)

We can add the `Hello.java` file under `<PROJECT_ROOT>/app/src/main/java/com/example/`.  
The `build.gradle` file should be updated with the main file : 

```groovy
plugins {
    // Apply the application plugin to add support for building a CLI application in Java.
    id 'application'
}

repositories {
    // Use Maven Central for resolving dependencies.
    mavenCentral()
}

dependencies {
    // Use JUnit test framework.
    testImplementation 'junit:junit:4.13.2'

    // This dependency is used by the application.
    implementation 'com.google.guava:guava:30.1.1-jre'
}

application {
    // Define the main class for the application.
    mainClass = 'com.example.Hello'
}
```

The project can be built and run with the Gradle CLI (using the Gradle wrapper) :
```shell
./gradlew build          # build Java .class files in the <PROJECT_ROOT>/app/build folder 
./gradlew run
```