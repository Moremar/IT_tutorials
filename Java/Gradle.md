# Gradle Tutorial


## Introduction

Gradle is one of the most popular open-source build automation tools for programming languages, both for open-source and enterprise projects.  
Gradle supports 2 DSL to write its instructions : **Groovy** and **Kotlin**.  

Gradle helps with the automation of software development and release.  
It can compile the source code, run tests and build binary artifacts.

Gradle is the primary automation tool for Android applications, it can also automate the build for Java, Go, or Python applications.  

Gradle is well integrated with most IDEs, like IntelliJ, Eclipse and NetBeans.  
It is also integrated with CI/CD products like Jenkins, TeamCity or GitHub actions.  


## Installation

Gradle runs on the JVM, so it requires a JDK or JRE to run.  
Gradle can be downloaded from https://gradle.org/install as a ZIP file containing a binary.  
It needs to be extracted in a directory that is in the PATH env variable.


## Groovy Basics

Groovy is the most popular DSL used for Gradle build scripts.

Groovy is a dynamic object-oriented programming language for the Java platform, more concise than Java.  
Groovy is a subset of Java, so any Java code is valid Groovy code.


```groovy
// define a list and iterate on it
def mylist = [ "item1", "item2", "item3" ]
mylist.each {
    println it
}

// define a class
class Player {
    String name
    Integer score

    Person(name, score) {
        this.name = name
        this.score = score
    }
    
    def increaseScore(points) {
        this.score += points
    }
}
```

Groovy is dynamically typed, so we can use either explicit types (like `int`) or the `def` keyword to infer the variable type.  

Strings can use interpolation with the `$` prefix to include the value of a variable.  
We can even use `${}` to include the value of a code expression (interpolation only works with double-quotes, not single quotes).

```groovy
def v1 = 12
int v2 = 13

println "v1 is $v1"
println "the sum is ${ v1 + v2 }"
```

### Functions

Groovy's functions return the value of the last instruction in their body.  
Groovy analyzes the entire script before executing code, so we can call a method in the build script before its declaration.

```groovy
int doubleNumber(int i) {
    i * 2
}
```

### Closures

Groovy **closures** are similar to lambdas in Java, they are executable blocks of instructions assigned to a variable.  
We can specify parameters in the closure with the `->` syntax at the beginning of the curly braces.  
If not specified, the closure takes an implicit parameter called `it` that can be referenced inside the closure body.

```groovy
Closure myClosure1 = {
    println "In closure 1"
}

Closure myClosure2 = { param ->
    println param
}

myClosure1()
myClosure2("In closure 2")
```

A closure can be passed as an argument to a function and executed within the function.  
That is used a lot in Gradle build scripts.

```groovy
// the "each" method of an array takes a closure and apply it to each element in the array
[1, 2, 3].each {
    println it
}
```


## Gradle Wrapper

Instead of having several versions of Gradle locally installed for each Gradle build, we can use the Gradle wrapper.  
The Gradle wrapper is a small script that downloads a specific version of Gradle and wraps it for the current build.  
It allows users to download and build the Gradle project even if they do not have Gradle installed locally.

Running `gradle wrapper` creates the wrapper components :
- the `gradlew` (Unix) and `gradlew.bat` (Windows) executables, to use instead of the `gradle` command to call the wrapper
- a `gradle/wrapper` folder containing :
  - `gradle-wrapper.jar`: a small JAR with the wrapper logic to download a version of Gradle and install it if needed
  - `gradle-wrapper.properties`: the wrapper properties file (including the URL of the Gradle version to use)

All these Gradle wrapper files are lightweight and should be added to the version control.  
These files should never be modified manually.  
The Gradle wrapper version can be queried or modified with the `gradlew` command :
```shell
gradlew --version                 // get the version
gradlew --gradle-version 7.2      // set the version
```

The Gradle version used by the wrapper can be specified in the `build.gradle` file by overriding the version in the `wrapper` task.  
This will create a wrapper with the specified version when running the `gradle wrapper` command :
```groovy
wrapper {
    gradleVersion = '4.0'
}
```


## Gradle Properties File

The `gradle.properties` file defines runtime options for the Gradle build.  
It is located in the root directory of the Gradle build.  
```
org.gradle.logging.level = info
version = 1.0.0
```

Gradle properties can be accessed in the build script of each project by key :
```groovy
task hello {
  doLast {
    println "Hello : version " + version
  }
}
```

Properties can also be passed to the Gradle build via the command line, with the `-p key=value` argument.

We can create a property dynamically by assigning it in the `ext` field object (key/value map for custom properties).  
We can update an existing property by assigning it (without the `ext` field, that is only for declaration).  
We can test for the existence of a property with the `hasProperty(str)` method.

```groovy
// create a property on a project
project.ext.myprop = 1

// update its value (no need to use "ext" here, only during declaration)
project.myprop = 2

// check for its existence and print it
if (project.hasProperty("myprop")) {
    logger.info "$myprop"
}
```



## Gradle Build Lifecycle

When we run Gradle, it goes through 3 successive phases :
 - the initialization phase
 - the configuration phase
 - the execution phase

### Initialization phase

In the initialization phase, Gradle evaluates the initialization scripts if present (`init.gradle` and/or others)
- these scripts are located under the `.gradle/init.d/` folder 
- these scripts can perform some initialization before the Gradle build
- these script can expose some variables (values or closures) in the `gradle.ext` object that will be available to all build scripts

```groovy
// expose a closure that returns the formatted current time
// it can be called in any Gradle build script with "gradle.timestamp()"
gradle.ext.timestamp = {
    def df = new SimpleDateFormat("yyyy-MM-dd'T'HH-mm-ss'Z'")
    df.setTimeZone(TimeZone.getTimeZone("UTC"))
    return df.format(new Date())
}
```
 
Gradle then evaluates the `settings.gradle` file if present.  
It is optional for single-project builds, but is required for multi-project builds.  
It specifies the name of the root project, and lists all sub-projects if any.  
It then creates a `Project` instance for each project.


### Configuration phase

During the configuration phase, Gradle evaluates the `gradle.build` script(s).  
For each of those scripts, it configures the corresponding `Project` instance.  

During this phase, Gradle also configures the `Task` instances for each of these projects.  
It builds a directed acyclic graph called the **task dependency graph** and makes it available in the Gradle object under `gradle.taskGraph`.  
This graph only contains the tasks that will need to be executed, so only the target tasks (or default tasks if no target tasks) and their dependencies.  
This graph is only ready at the end of the configuration phase.  
To apply a function on it when it is ready, we can use its `whenReady` method that takes a closure as parameter :
```groovy
gradle.taskGraph.whenReady {
    logger.info "Tasks : $gradle.taskGraph.allTasks"
}
```

The task graph exposes the `beforeTask` and `afterTask` hooks that we can use to execute code before/after the execution of specific tasks :
```groovy
gradle.taskGraph.beforeTask { task ->
    logger.info "DEBUG Executing task $task.name"
}
```
 
### Execution phase

After the configuration phase, Gradle enters the execution phase, when it executes the code of the requested task(s).  
For each of the requested tasks, it finds from the dependency graph if other tasks must be executed before, and executes these tasks in the correct order.  

A task can include instructions in a `doFirst` or in a `doLast` block, to execute these instructions before or after the existing actions.  
This is useful to add custom initialization of cleanup when we extend an existing task that already has a actions.

We can configure one of more default tasks in a Gradle build script.  
These tasks will be run when running the `gradle` command with no task name.

```groovy
defaultTasks 'clean', 'build'
```


## Gradle API

### Script Interface

A **Gradle script** is any file with the `.gradle` extension.  
For each Gradle script, Gradle creates an instance of a class implementing the `Script` interface.  
This gives access to this interface's properties and methods to all Gradle scripts, for example the `logger` property.  
Note that for the log to be displayed, we need to use the `-i` option in the `gradlew` command.

```groovy
logger.info "This is an INFO log using the logger in the Script interface"
```

Each Gradle Script has a delegate object of a different class.  
When a property or method is not found in the script object, it is forwarded to its delegate object.  

The delegate object is different depending on the script :
- the Script for `init.gradle` will have a delegate of class `Gradle` 
- the Script for `settings.gradle` will have a delegate of class `Settings`
- the Script for `build.gradle` will have a delegate of class `Project`

### Gradle Interface

At the very beginning of a Gradle build, when Gradle does not know any details about the build, it create an instance of the `Gradle` interface.  
This is used by the initialization scripts to expose some objects to the build.  
The `Gradle` instance exposes some useful properties about the Gradle build : `gradleVersion`, `gradleHomeDir` ...  
Those properties can be accessed via the `gradle` property of the `Project`, `Settings` or `Gradle` instance.

### Settings Interface 

During a Gradle build, Gradle instantiates a single object implementing the `Settings` interface.    
It then configures it using the `settings.gradle` file.   
There is a 1-to-1 mapping between a `settings.gradle` file and a `Settings` instance.  
The settings object's primary purpose is to keep track of all the projects that make up the Gradle build.

### Project Interface

A **Gradle project** is a piece of software that can be built, like an application or a library.  
Every Gradle build includes at least one project, called the root project.  
A Gradle build can include any number of sub-projects.  

For each `build.gradle` file, Gradle instantiates an object implementing the `Project` interface.  
A project is basically a collection of Gradle tasks.

### Task Interface

A **Gradle task** is an atomic unit of work that can be executed in a Gradle project, such as compiling code or running tests.  
The syntax depends on the DSL chosen to write the build script.

A task is made up of a sequence of `Action` objects, that are individual commands that the task will perform sequentially.  

We can add an action to a task with the `doFirst` and `doLast` methods of the `Task` interface, that take a closure as parameter.  
This happens in the configuration phase, when the tasks are being built (the actions are not executed yet).

A Gradle task can be either ad-hoc or typed.    

An **ad-hoc task** is used for a one-off simple task.  
It extends the `DefaultTask` class, and its action is fully defined in the build script.  

```groovy
// Groovy DSL (build.gradle)
task hello {
  // set some task properties
  description = "Greet the user"
  group = "welcome"
  // add an action
  doLast {
    println "Hello"
  }
}

// Kotlin DSL (build.gradle.kts)
tasks.create("hello") {
  doLast {
    println("Hello")
  }
}
```

A **typed task** explicitly specifies a task type, and extends its specific implementation.  
It does not need to specify any action, as the action is already specified in the parent implementation.  
A typed task's body usually only contains configuration, for example a copy task would configure its source and destination folders :  

```groovy
task copyHeaders(type: Copy) {
  from "src"
  into "build/src"
  include "**/*.h"
}
```  

Gradle supports dependencies between tasks with the `dependsOn` method called from a task.  
A task can depend on multiple tasks, but the execution order of the dependencies is not guaranteed.  
There should be no cycle in the task dependencies graph.
```groovy
task createZip(type: Zip) {
  from "build/src"
  archiveFileName = "headers.zip"
  destinationDirectory = file("build/dist")
  dependsOn copyHeader                          // define a dependency on other tasks
}
```


## Gradle Plugins

A **Gradle plugin** is a piece of software that extends the capabilities of the build system.  
It can define new tasks, configurations or other build components.  
Plugins are imported in the `build.gradle` file to provide their capabilities to a project build.

There are 2 types of Gradle plugins :
- **script plugin** : another build script that can be included in the main gradle build file with the `apply from: "myscript.gradle"` instruction
- **binary plugin** : designed for more complex logic, implemented as files and bundled as a JAR file, a lot of binary plugins are available on the Gradle plugin portal

Some commonly used binary plugins are :
- `base` : common features for many projects across languages, adding the clean, assemble and check tasks, and setting default locations for generated files (in a `dist` folder)
- `java` : add tasks to compile Java code, run tests and package the Java application
- `application` : simplify the creation of a Java application with a `main()` method
- `maven-publish` : provide functionality to publish the JAR to a Maven repository
- `checkstyle` : integrate with the Checkstyle static code analysis tool to improve code quality
- `spotbugs` : Java code static analysis tool to detect potential bugs (null pointer exceptions, dodgy method calls...)
- `pmd` : also a Java static code analyzer, but focusing on code quality (dead code, coding style violation, bad practices... )
- `jacoco` : integrate with the Jacoco code coverage metrics tool

Some code analyzer plugins like `spotbugs` and `pmd` add a dependency to the `check` task defined in the Java plugin.  
When running the `check` task with these plugins configured, Gradle will perform the code analysis and generate a report.  
An example is available in my Advent of Code 2017 Java solutions : https://github.com/Moremar/advent_of_code/blob/main/aoc_2017/build.gradle

The Gradle official website offers in-depth documentation, tutorials and explanations of plugins for common scenarios.

```groovy
plugins {
    id 'base'
}

task createTar(type: Tar) {
  doFirst {
    println "Before my task"
  }
  doLast {
    println "After my task"
  }
  from '.'
  include '*.txt'
  into 'level1'
  rename '(.+).txt', '$1.text'
  compression = 'GZIP'
  destinationDirectory = file("./build/")
  archiveBaseName = "myTxtArchive"
}
```

## Gradle CLI

All below commands can be called with `gradlew` instead to use the Gradle wrapper.

```shell
gradle -v                # display Gradle version
gradle projects          # list all projects inside this gradle build
gradle tasks             # list all available tasks in this project

gradle                   # execute the default task(s)
gradle mytask            # execute a task
gradle myTask --dry-run  # show the tasks that would be executed, without actually executing them
gradle -i mytask         # execute a task and enable the logging (called to logger.info)
gradle mytask --age=13   # execute a task with a parameter

gradle wrapper           # creates the wrapper components
gradle init              # create a Gradle project (build.gradle + settings.gradle + wrapper)
```


## Gradle for Java

Gradle supports multi-project builds, with one `build.gradle` file at build root level for common configuration across all sub-projects,
and one `build.gradle` file in each sub-project.

In a Java application, a sub-project corresponds to a Java module.  
The `settings.gradle` file in the root directory defines the root project name and its sub-projects (mandatory for multi-projects build).  
Before Gradle assembles the projects for the build, it reads this settings file and creates the corresponding `Settings` object.  
All methods invoked in the `settings.gradle` file are actually methods on this `Settings` object from the Gradle API.

The `java` plugin adds the required tasks for Java documentation, compilation, testing and JAR creation.  
It also relies on conventions regarding the folder structure and the file naming.  
The default convention is to use the same structure as a Maven project, with source code under `src/main/java` and test code in `src/test/java`.

The repositories used to fetch the external JARs required by the Java application can be specified in the `repositories` block.  
The most common repository is Maven Central that can be specified with the `mavenCentral()` method.

Once the repositories are configured, we need to specify which dependencies Gradle should fetch (JAR group + name + version).  
In the `dependencies` block, we specify if each dependency is required by the project implementation (`implementation`) of for testing only (`testImplementation`).  
We then specify the Gradle coordinates of the dependencies (available on MVN Repository website).

Exposed tasks can be configured by specifying some of the properties that they expose.

```groovy
plugins {
  id 'java'
}

repositories {
  mavenCentral()
}

dependencies {
  implementation 'org.apache.commons:commons-math3:3.6.1'
  testImplementation 'junit:junit:4.12'
}

// configure the jar task
jar {
  // the "-all" suffix is a convention for a fat JAR
  baseName = "$project.name-all"
  manifest {
    // the attributes in the MANIFEST file are set by the Java MANIFEST specification
    attributes 'Implementation-Title' : 'JAR including all dependencies',
               'Implementation-Version' : version,
               'Created-By' : 'userA',
               'Main-Class' : 'com.myproject.App'
  }
  // force Gradle to copy all dependencies into the jar (fat-jar)
  from {
    project.configurations.runtimeClassPath.collect(File file -> project.zipTree(file))
  }
} 
```

The `dependencies` task prints the dependencies tree of the Java project for each scope.  
The `implementation` scope only shows direct dependencies, while the `runtimeClassPath` scope also shows transitive dependencies.  
We can also have an HTML report of the dependencies by using the `htmlDependencyReport` task provided by the `project-report` plugin.  


## Multi-Project Build

Splitting a build into multiple Gradle projects is a good practice for big projects.  
It allows the grouping of code into loosely coupled sub-projects.  
In a Java project, each sub-project will have its own JAR, that can be used by other sub-projects.  

A multi-project build always has a root project, with multiple sub-projects.  
Each sub-project can also have sub-projects, there are no depth limit (it is defined by the file hierarchy).

The root project must have a `settings.gradle` file that specifies the sub-projects of the build.  
It can also contain other configuration elements, like the root project name and some plugin info to share between sub-projects.


#### Example of settings.gradle
```
// define project name
rootProject.name = "hello-project"

// define the location of Gradle plugins
pluginManagement {
  repositories {
    gradlePluginPortal()
    google()
  }
}

// specify plugins to include at settings level
// these allow plugins that influence the build process, or allow all sub-projects to use a consistent version of a plugin
plugins {
  id 'org.gradle.toolchains.foojay-resolver-convention'
  version '0.8.0'
}

// specify the repositories to get dependencies from
dependencyResolutionManagement {
  repositories {
    mavenCentral()
  }
}

// list sub-projects (only this part is mandatory for a multi-project build)
include("sub-project-1")
include("sub-project-2")
```

The `build.gradle` file of the root project can include a `subprojects` block that takes a closure as parameter.  
All the configuration in the block will be shared between all sub-projects.

```groovy
subprojects {
    // apply a plugin to all sub-projects
    apply plugin: 'java'
    
    // set some common properties for all sub-projects
    group = 'com.myapp'
    version = '1.0.0'
    sourceCompatibility = 1.8
    targetCompatibility = 1.8
  
    // common repository for all sub-projects
    repositories {
      mavenCentral()
    }
}

// configuration specific to a sub-project to set a dependency
project(':sub-project-2') {
    dependencies {
        implementation project(':sub-project-1')
    }
}
```