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

- **range of values** : with the `Stream.range(startVal, endVal)` static method

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

