# Bash Scripts


## Introduction

Bash (Bourne Again Shell) is both an interactive shell and a scripting language for Unix systems.  
It can be used to automate tasks instead of using an additional scripting language like Python.  
It is recommended to not use Bash for scripts longer than 100 lines of code (beyond that, use Python).

Every Bash command that we can run in the terminal can be used in a Bash script.  
A Bash script usually has the `.sh` extension, and users must have execute permission on it to run the script.  

Google provides a [Shell Style Guide](https://google.github.io/styleguide/shellguide.html) with best practices during Bash script development.


## Bash Basics

### Shebang

A Bash script starts with a shebang, so we can execute it directly without explicitly calling the `bash` command.  
The shebang specifies the executable to run the script (this is not Bash-specific, it is also used for Python).

A common shebang for Bash is `#!/bin/bash` that hardcodes the path of the `bash` command to use.

A more recent shebang is `#!/usr/bin/env bash` that looks in the environment for the the `bash` command.  
This is preferred, as it allows to control the `bash` command to use from the `PATH` environment variable.  
This allows for example on MacOS to use a more modern version of Bash than the old one installed by default.

Note that from a Bash perspective, the shebang is just a comment and is ignored (because it start with `#`).  
It only has a meaning to the OS, that uses it to decide the binary to use to execute the script.

```shell
#!/usr/bin/env bash
echo 'I am a Bash script'
```

### Comments

Comments in Bash start with `#` and are ignored by the `bash` command during execution.  

Some people use `:` for comments, but that is not technically a comment.  
`:` is an actual command, it is the **no-op command**, that simply returns a success status.  
Unlike a comment, the following part is evaluated (and then discarded).  
This means that any expansion following `:` would be executed.

```shell
# $(ls > test.txt)              # comment, so the command expansion is not executed
: $(ls > test.txt)              # no-op command, so the command expansion is executed and test.txt is created
```

Bash does not have multi-line comments, we should just use `#` on each line.  

Some people use as a hack the `:` command and send to its stdin a heredoc temporary file.  
Note that this is not a comment and it should be avoided for multi-line comments !
```shell
: << HEREDOC_DELIMITER
Aaaa bbbb ccc
ddd eee
HEREDOC_DELIMITER
```

### Bash Variables

Bash variables are valid only for the current bash session.  
When a Bash script is executed, it executes in its own Bash session, so Bash variables no longer exist after execution.

Bash variables are case-sensitive, and by convention should only be lower-case with underscore (snake-case).  
Variables must be defined with a `=` and NO SPACE around it.  
All Bash variables are strings, the use of quotes only defines the Bash expansion to apply.

File expansion is disabled in variable declarations, so `*` would not be expanded.  
Command and variable substitutions are enabled in variable declarations.

Bash variables can be used with variable expansion, using the `${my_var}` structure.

```shell
my_age=23                             # string "23"
my_name='John Smith'                  # string "John Smith" (with expansion disabled)
my_desc="${my_name} (${my_age})"      # string "John Smith (23)" using variable expansion
my_output="$(echo Hello)"             # string "Hello" using command substitution                     

echo "Details : ${my_desc}"           # use the Bash variables by variable expansion   
```

Note that there should be no space around the `=` sign when declaring a Bash variable.  
If we use a space, it has a totally different meaning :
```shell
my_var=val                     # create a Bash variable with value "val"
my_var= val                    # try to run the "val" command with an env variable equal to "" 
my_var =val                    # try to run the "my_var" command and give it parameter "=val"
my_var = val                   # try to run the "my_var" command and give it 2 parameters  "=" and "val"
```

We can also explicitly use the `declare` command when declaring a variable.  
It is usually optional, but it is required when using ommand options.
```shell
my_var=val                     # create a Bash variable with value "val"
declare my_var=val             # same with explicit "declare" command
                               #  -r : declare a READ-ONLY Bash variable
                               #  -i : declare an integer variable
                               #  -x : declare an environment variable
declare -p                     # list of all defined variables with their options
```

Bash variables are short-lived so we usually do not need to unset them.  
They can either be left defined until script end, or assigned the empty string.  
If we really want, we can manually unset them anyway :
```shell
unset my_var              # unset a variable so it is no longer listed with "declare -p"
```


#### Bash variables VS Environment variables

Environment variables are a feature of the OS independent of Bash and are inherited by child processes.  
They are created with the `export MY_ENV_VAR='Tom'` syntax, with a name in upper-case. 

Bash variables are not inherited by child processes, their scope is limited to the current bash session.

We should use Bash variables when possible to avoid polluting the environment of child processes.


### User input

Some user input can be obtained and stored in a variable with the `read` command.  
Note that the `read` command is a Bash-specific command, so it may not be supported by other shells (like ZSH).

```shell
read -p "Name : " name          # print "Name : ", ask for user input and store it in the name variable
                                #  -d DELIMITER : use a specific delimiter (instead of new line)
                                #  -a : assign the user input to an array variable
                                #  -s : do not show in the Bash the text written by the user  
                                #  -r : prevent multi-line with Backslash-Enter (Enter ends the input)
read var1 var2                  # read 2 variables from the input, separated by space (IFS variable)
                                # if there are more spaces, all the rest goes to the last variable

IFS=',' read var1 var2 var3     # read multiple variables from user input separated by commas
                                # the IFS Bash variable is only overridden for the duration of the read command

read hour rest < <(uptime)      # get the first part of the uptime command in the "hour" variable
uptime | read hour rest         # THIS DOES NOT WORK THE SAME, WE SHOULD USE THE ABOVE INSTEAD ! 
                                # It creates the hour variable in a sub-shell, no longer accessible after the command !
```

To load the content of an entire file in a variable, we can use the `cat` command.  
A more efficient syntax is to use the `<` operator :
```shell
var1="$(cat file.txt)"          # insert file content in a variable with cat
var1="$(< file.txt)"            # more efficient syntax with <
```

##### Difference between pipe and command substitution

`ls | wc -l` executes the `ls` command in the main shell, and `wc` in a sub-shell.   
`wc -l < <(ls)` executes the `ls` command in a sub-shell, and `wc` in  the main shell.  

In most cases it does not make a difference, but it matters when commands have shell-level side effects.  
For example, if one of the commands creates a Bash variable, it is only available to next commands if executed in the main shell.

`echo "Linux" | read my_os` creates the `my_os` Bash variable in a sub-shell that is not accessible in the main shell.  
`read my_os < <(echo "Linux")` creates the `my_os` Bash variable in the main shell, so the main shell can use it.


### Simple Script Example 

```shell
#!/usr/bin/env bash

# declare READ-ONLY style variables
declare -r green="$(tput setaf 2)"
declare -r reset="$(tput sgr0)"

# prompt for user input and print message
read -p "Name: " name
echo "Hello ${green}${name}${reset}!"

# print number of files in a folder
file_count="$(ls | wc -l)"
echo "File count: ${file_count}"
```

### Multi-files Script

From a parent script, we can call a child script, either with `bash child.sh` or `./child.sh`.  
The child script runs in its own Bash session.  
Bash variables defined in the parent are not visible to the child script.  
Environment variables defined in the parent are visible to the child script (inherited).  
Both Bash and environment variables defined in the child script are not visible to the parent script.

To run the child script in the same Bash session as the parent, we use the `source child.sh` command.  
It runs all commands from the child script as if they were part of the parent.  


### ShellCheck

`shellcheck` is a program that validates Bash scripts for syntax errors and common mistakes.  
When it detects a potential issue, it suggests a fix and links to a documentation of the issue.  

It needs to be installed with `sudo apt install shellcheck`.

Shellcheck can also be installed as an extension in Visual Studio Code.


### Arithmetics

#### Integers

We can perform arithmetic operations in a Bash script by including them in `(( ... ))` (math mode).  
In math mode, we do not need to use the `$` in front of variable names.

We can also create a math expression with `"$(( ... ))"` that is expanded by Bash.  
We should include the math expression in double quotes to avoid troubles with unexpected Bash expansion.

```shell
a=1
b=2
(( sum = a + b ))      # math mode
echo $sum

echo "$(( a + b ))"    # math expansion
```

Variables can be declared as integers with `declare -i my_var`.  
When declared as integers, variables automatically evaluate the expression when assigned.  
```shell
declare -i my_int
my_int="1+2"             # evaluated to 3 instead of the string "1+3"
echo $my_int
```

We can read an integer variable from the user with the `read` command.  
However, that implies the evaluation of the command, exposing any existing variable in the Bash session.  
We may prefer to read it as a string, and trim it ourselves to avoid auto-evaluation.
```shell
declare -i my_var1            # declare the integer variable without a value
read my_var1                  # prompt for a value and evaluate it, so if we type "1+1" it evaluates to 2

declare my_var2               # declare the variable as a string
read my_var2                  # prompt for a string value for the my_var2 variable
my_var2=${my_var2//[^0-9]/}   # replace all non-digit characters by an empty string
```

In native Bash, arithmetics only works with integers.  
Operations on decimals are limited to integer division and remainder with the `/` and `%` operators.  

For decimal calculation, we use the `bc` command (basic calculator) that resolves a math string.  
```shell
echo "2.5 * 3" | bc             # return 7.5
echo "10 / 3" | bc              # return 3 (by default use integer division)
echo "scale=2; 10 / 3" | bc     # return 3.33 (set the scale to 2 decimals)

my_val='2.4'
echo "${my_val} * 2" | bc       # return 4.8, usual Bash variable expansion applies to the string 
```


## Bash Control Flow


### true / false

When a Linux program exits, it returns an 8-bit exit code between 0 and 255.    
This code is 0 for SUCCESS and any other value for FAILURE (usually 1).  
The variable `$?` provides the exit code of the last command.  
In Bash `true` is a command that returns the exit code 0, and `false` is a command that returns the exit code 1 !
```shell
true ; echo $?                # print 0
false ; echo $?               # print 1
```

### Command chaining

There are multiple constructs to chain commands :
```shell
<COMMAND_1> ; <COMMAND_2>          # always execute both commands
<COMMAND_1> && <COMMAND_2>         # logical AND : execute the 2nd command only if the first succeeds (exit code 0)
<COMMAND_1> || <COMMAND_2>         # logical OR : execute the 2nd command only if the first fails (exit code 1 or more)
```

### Conditions

To test a condition we use the `[[ <CONDITION> ]]` structure, that has an exit code of 0 on success and 1 on failure.  
The spaces next to the double square brackets are required for Bash to know where to start and end the condition !  
```shell
name="aaa"
[[ "${name}" == "bbb" ]]                # evaluate the condition to false so exit code 1
echo $?                                 # print the exit code 1 of the condition
```

**Pattern matching** can be used between the double square brackets with `[[ <STRING> == <PATTERN> ]]`  
Pattern matching is a simplified regex syntax where `?` indicates a single character and `*` any sequence of characters.  
Pattern matching is a full-match, so the entire string has to match the entire pattern.  
Filename expansion is disabled inside a condition, so `*` can only have its pattern matching meaning.
```shell
[[ "${name}" == *.txt ]]      # match any file ending with .txt
```

For more complex checks, we use regex instead of simple pattern matching, with `[[ <STRING> =~ <REGEX> ]]`  
Regex return true if the regex is found in the string, not necessarily covering the entire string.
```shell
[[ "${name}" =~ \.txt$ ]]     # match any file ending with .txt
```

Tests if a string is empty or not :
```shell
# true if the string is empty
[[ "${my_var}" == '' ]]
[[ -z "${my_var}" ]]

# true if the string is not empty
[[ "${my_var}" != '' ]]
[[ -n "${my_var}" ]]
```

Tests on a file :
```shell
[[ -e file.txt ]]        # check if a file exists
[[ -f file.txt ]]        # check if a file is a regular file
[[ -d file.txt ]]        # check if a file is a directory
[[ -r file.txt ]]        # check if a file has READ permission
[[ -w file.txt ]]        # check if a file has WRITE permission
[[ -x file.txt ]]        # check if a file has EXECUTE permission
```

Logical NOT / AND / OR :
```shell
[[ ! -e 'test.txt ]]                      # test for non existence
[[ -e 'test.txt && -f 'test.txt ]]        # logical AND with &&
[[ -e 'test1.txt || -e 'test2.txt ]]      # logical OR with ||
```

Tests on numbers :
```shell
# with [[ ... ]] conditions we can use the -lt / -le / -gt / -ge operators
[[ "${age}" -lt 25 ]]    # check if a value is < 25
[[ "${age}" -le 25 ]]    # check if a value is <= 25
[[ "${age}" -gt 25 ]]    # check if a value is > 25
[[ "${age}" -ge 25 ]]    # check if a value is >= 25

# we can also use a math expression as a condition with (( ... )) to get a better syntax
(( age > 25 ))
(( age >= 25 ))
(( age < 25 ))
(( age <= 25 ))
```

Note that the `[ ... ]` syntax ot the `test` command are sometimes used instead of `[[ ... ]]` for conditions.  
They are similar, but should be avoided because they call external programs instead of using Bash built-in conditions.  
As a result, they do not support regex and pattern matching, instead filename expansion applies.  
They exist only for compatibility reasons with old code, but should no longer be used.
```shell
[[ "${name}" == "Bob" ]]         # double square brackets (Bash built-in condition)
[ "${name}" == "Bob" ]           # single square bracket calling /bin/[
test "${name}" == "Bob"          # calling /bin/test

[[ "test.txt" == *.txt ]]        # return 0 with pattern matching
[ "test.txt" == *.txt ]          # fail because it performs filename expansion
test "test.txt" == *.txt         # fail because it performs filename expansion
```

### if / elif / else block

```shell
# usual styling
if [[ "${name}" == "Tom" ]]
then
    echo "Hi Tom"
fi

# one-line version, note there is no ; after the "then"
if [[ "${name}" == "Tom" ]] ; then echo "Hi Tom" ; fi

# the if construct can use commands instead of conditions
if <COMMAND>
then
   <COMMAND_1>                 # execute if <COMMAND> had exit code 0
else
   <COMMAND_2>                 # execute if <COMMAND> had exit code 1 (or anything not 0)
fi

# different style with the "then" on the same line as the "if"
if ping aaa ; then
    echo "ping aaa success"
elif ping bbb ; then           # elif for another condition check in case of failure
    echo "ping aaa success"
else
    echo "ping failed"
fi
```


### case block

```shell
# General syntax of a case block
case <EXPRESSION> in
  <PATTERN_1>)
    # code to execute if the EXPRESSION matches PATTERN_1
    ;;
  <PATTERN>)
    # code to execute if the EXPRESSION matches PATTERN_2
    ;;
  *)
    # code to execute otherwise
    ;;
esac

# Example of a case block
case "${name}" in 
  Bob)
    echo "Hi Bob"
    ;;
  Mary)
    ;&                  # specify to go to the next case (instead of ;; to break)
  Alice|Anna)
    echo "Hello girl"
    ;;
  *)
    echo "Hi there"
    ;;
esac
```

### while loop

```shell
# General syntax of a while loop
while <COMMAND OR CONDITION>; do
  # code to execute
done

# Example of a while loop
step=0
while (( step != 100 )); do
  (( step = step + 1 ))
  if (( step == 3 )) ; then
    continue                    # skip the processing on step 3
  fi
  if (( step == 6 )) ; then
    break                       # exit the while loop on step 6
  fi  
  echo "Step ${step} ..."
done

# Example of a while loop to read a file line by line
# we override IFS to the empty string to not trim the lines, and store the line in a Bash variable
# "read -r" specifies to not interpret the \ as an escape character (so \n or \t are not interpreted as newline or tab)
while IFS= read -r myline; do 
  echo "Got line : ${myline}"
done < file.txt                       # feed a file to the while loop
```


### for loop

```shell
# General syntax of a for loop
for my_i in <ELEMENTS>; do
    # code to execute
done

# basic example of for loop
for my_name in John Bob Alice; do
    echo $my_name  
done

# for loop with sequence expansion
for my_i in {1..10} ; do
    echo $my_i
done

# for loop with filename expansion and brace expansion
# note that *.txt returns "*.txt" in case there are no txt file in the folder, so we check for file existence !
for my_file in ./*.{txt,log} ; do
    if [[ -f "${my_file}" ]] ; then
        echo $my_file
    fi
done

# for loop with command expansion
for token in $(uptime) ; do
    echo "Token: ${token}"
done

# when the loop scope is dynamic, we can use the "seq" command (brace expansion does not work with variable expansion)
for my_i in $(seq 1 ${my_max}) ; do
    echo $my_i
done

## General syntax of a for loop using a math expression
for (( <INIT> ; <TEST> ; <AFTER> )) ; do
    # code to execute
done

# example of a for loop using a math expression
for (( my_i = 0 ; my_i < 10 ; my_i++ )) ; do        # in math mode, the ++ operator is supported
    echo $my_i
done
```

### select loop

The select loop is a Bash built-in structure that lets the user choose between multiple values.  
At execution, Bash presents all options with an index starting from 1.  
The user must enter the index of an option, and Bash assigns the corresponding value to the select variable.  
Bash also exposes the chosen index with the `$REPLY` variable.  
We can overwrite the prompt string before the user reply with the `PS3` variable (it display `#?` by default).

```shell
# Generic syntax of a select loop
PS3="Select an option : "
select my_option in option1 option2 option3 ; do
  echo "Chose option $REPLY : $my_option"            # REPLY is the user entered index, my_option is option1, option2, option3 or empty
  break                                              # loop until we break
done

# Combine a select loop with a case block
PS3="Choose info: "
select info in Name Age Hobby ; do
  echo "You selected option $REPLY"
  case $info in
    Name)  echo "Alice" ;;
    Age)   echo "25" ;;
    Hobby) echo "Dance" ;;
    *)     echo "Invalid response, select a valid option."
           continue ;;
  esac
  break
done
```

### dialog command

The `dialog` command opens an in-shell dialog for richer user interactions than the `select` loop.  
It returns the selected option by exit code, so it can easily be used inside a Bash script.  
For dialogs that return a value (inputbox or menu), the result is sent to stderr (since stdout is used for display).

Some parameters are common to all types of dialogs :
- `--title <TITLE>` : specify a title for the dialog
- `--backtitle <TITLE>` : specify a title for the background
- `--keep-tite` : delete the dialog from the shell after user response

```shell
sudo apt install dialog

# open an in-shell info pop-up with custom text and an OK button (specify number of lines and columns, 0 for auto)
# it returns exit code 0 on OK and 1 on Ctrl-C
dialog --title "Nice Title" --backtitle "Nice Back Title" --msgbox "Nice shirt bro!" 0 0

# open an in-shell Yes/No dialog
# it returns exit code 0 on Yes and 1 on No or Ctrl-C
dialog --yesno "Need a hug ?" 0 0

# open an in-shell input dialog where the user can enter some text
# the user input is sent to stderr
dialog --inputbox "Any question ?" 0 0 2>response.txt

# when used in a Bash script, we can capture the output of the inputbox dialog in a variable
# For that, we redirect stderr to stdout and stdout to /dev/tty, so we get only stderr in the variable
response=$(dialog --keep-tite --inputbox "Any question ?" 0 0 2>&1 >/dev/tty)

# open a menu dialog to choose from a set of values
# each value has a tag and a description
# we can hide the tag from the displayed menu with the --no-tags parameter
# the selected tag is returned in stderr
# we can specify the number of lines and columns of the dialog, and lines of the menu (0 for auto)
dialog --keep-tite --no-tags --menu "Choose info:" 0 0 0 "name" "Name" "age" "Age" 2>response.txt
```

Example in-shell GUI program to ask for student names and save them in a file :
```shell
#!/usr/bin/env bash

while true ; do

  # in-shell input box to get a student name
  student_name=$(dialog --keep-tite --title "Student Record" --inputbox "Enter a student name:" 0 0 2>&1 >/dev/tty)

  # exit if the user selected Cancel
  exit_code=$?
  if (( exit_code != 0 )) ; then
    break
  fi

  # save the student name in a file if not empty
  if [[ -n $student_name ]] ; then
    echo $student_name >> students.txt
  fi

  # in-shell yes/no box to ask if we should continue
  if ! dialog --keep-tite --title "Student Record" --yesno "Continue ?" 0 0 ; then
    break
  fi

done
```

### zenity command

For GUI dialogs (instead of in-shell dialogs) we can use the `zenity` program instead.  
Zenity requires a GUI to be available on the machine, so it does not work with a remote SSH connection.  

Zenity supports **Pango markup language**, so we can style the text with `<b></b>`, `<i></i>` ...  
Unlike `dialog`, Zenity creates a GUI for its dialog (not stdout) so it uses stdout for the output (not stderr).  

```shell
sudo apt install zenity

zenity --help                      # top-level help
zenity --help-general              # help on general options
zenity --help-question             # help on question dialog specific options (each dialog type has its help option)

# open a yes/no dialog, with exit code 0 (Yes) or 1 (No)
zenity --question --title "Check" --text "Are you OK ?"

# open a dialog where the user can enter custom text, and return the user text to stdout
zenity --entry --text "Any question ?"

# saving the output of an entry dialog to a variable is easier than with dialog, because it does not need redirection
response=$(zenity --entry --text "Any question ?")
```

## Script Arguments

### Bash argument variables

A Bash script can accept any number of parameters when called from a shell.  
Bash exposes several Bash variables used to interact with arguments :
- `$0` : name of the script that is being executed  
- `$1`, `$2`, `$3` ... : positional arguments given to the script in the command line
- `$#` : number of positional arguments
- `$@` : array containing all positional arguments
- `$*` : single string containing all positional arguments
- `$$` : current process ID

### shift 

The `shift 1` commands can be used if we want to write a Bash script with a dynamic number of arguments.  
It throws away the first argument, and shifts all remaining arguments by one position to the left.  
It also updates the value of `$#` to the number of remaining positional arguments.  
This way we can write a while loop that reads the first argument, processes it if not empty, then shifts the remaining arguments.
```shell
while (( $# != 0 )) ; do
  echo "Processing argument: $1"
  shift 1
done
```

### getopts

We can accept options in a Bash script like `-a` or `-l`, or multiple options together like `-al`.  
Instead of parsing manually the options provided by positional arguments (like `$1`), we can use the `getopts` command.  
It takes a list of supported options, and a variable where it stores one of the received options.  
Multiple calls to `getopts` will return all the provided options one by one.  
`getopts` return exit code 0 when an option is read, and 1 when no more option can be read.

```shell
# when ran in a script called with ./script.sh -al -o
getopts 'alo' option         # option stores "a", exit code 0
getopts 'alo' option         # option stores "l", exit code 0
getopts 'alo' option         # option stores "o", exit code 0
getopts 'alo' option         # no more option to read, exit code 1
```

`getopts` also supports options with a value, by adding `:` after the option name.  
The value is stored in the `$OPTARG` variable.

```shell
# when ran in a script called with ./script -o a.txt
getopts 'o:' option
echo "$option $OPTARG"     # o a.txt
```

`getopts` is often used with a while loop and a case block to process all options.  
We can redirect its stderr to avoid having messages in the terminal on invalid options.

```shell
while getopts 'alo:' option 2>/dev/null ; do
  case $option in
    a) echo "option all" ;;
    l) echo "option list" ;;
    o) echo "option output $OPTARG" ;;
    *) echo "invalid option" ; exit 1 ;;
  esac
done
```


## Bash Functions

Bash Functions can be defined in a Bash script when a block of code needs to be re-used.  
Just like a Bash script, a function can access its parameters with the Bash argument parameters.  
`$0` is the name of the Bash script, and `$1` is the first argument received by the function.  
Unlike common programming languages, function parameters are not specified in the function definition.

```shell
# function definition
my_func() {
  echo "called my_func from script $0 with $# arguments : $*"
}

# alternative function definition with the "function" keyword, in that case brackets are optional
function my_func2 {
  echo "called my_func2"
}

# function invocation
my_func a b c             # called my_func from script ./script.sh with 3 arguments : a b c
```

Variables have a global scope within a Bash script.  
Any variable defined in the script or inside a function is visible to the rest of the script, and inside other functions.  
We can define a variable inside a function with the `local` keyword to limit its scope to this function.

```shell
my_func() {
  local v1="V1"
  v2="V2"
}

my_func      # execute the function
echo $v1     # empty because v1 is local to the function
echo $v2     # V2, because v2 is global 
```

We can implement a function that allows an argument to be provided or not, by defaulting the value of the parameter :

```shell
function my_func {
  local msg=${1:-"Hello"}     # default to "Hello" if $1 is empty
  echo "$msg"
}
```

A function can use the return command to return a custom exit code (0 by default).  
Unlike most programming languages, the return value of a function only represents its exit code, not a value it computed.  
To return other custom values, we can either store it in a global variable (to avoid), or send it to stdout.  

```shell
function my_func {
  echo "Hello $1"
}

msg=$(my_func 'Bob')
```


## Arrays

Bash arrays behave differently from other programming languages.  
A normal Bash variable is just a 1-size array variable.  
An array variable returns its first element when used without index.  

Bash supports array expansion with `${my_array[@]}` to expand an array to one word per element in the array.

Another expansion is `${my_array[*]}` that creates a string of all elements of the array separated by a space.  
It behaves the same as `${my_array[@]}` with `echo` but has a different meaning since the separation between words is lost.

```shell
my_array=(aaa bbb ccc)                 # use brackets to define an array
declare -a my_array=(aaa bbb ccc)      # explicitly declare an array variable

echo ${my_array}                       # aaa : default to my_array[0]
echo ${my_array[1]}                    # bbb
echo ${my_array[3]}                    # empty string since above the amx index
echo ${my_array[-1]}                   # ccc (negative indexes start from the end)

echo ${my_array[@]}                    # aaa bbb ccc  (array expansion)
echo ${my_array[*]}                    # aaa bbb ccc  (all values separated by a space)

my_array[1]="BBB"                      # override an element of the array
my_array[3]="ddd"                      # add an element to the array at a specific index

# normal variables are just 1-size arrays
my_var=2
my_var[0]=3                               # override my_var
echo ${my_var[@]}                         # print the value of my_var

${#my_array[@]}                           # size of the array
${#my_array[*]}                           # same
my_array+=(eee)                           # add an element to the array
unset my_array[2]                         # delete element at position 2 (but no shift of next elements, just create a hole in the array)
${my_array[@]:2:3}                        # slice of the array, starting at index 2 and containing 3 elements
my_copy=("${my_array[@]}")                # create a copy of an array
my_new=( "AAA" "${my_array[@]}" "BBB" )   # create a new array containing all elements of an array, and other elements

# for loop on elements of an array
for elem in "${my_array[@]}" ; do
  echo "$elem"
done

# select loop on elements of an array
select elem in "${my_array[@]}" ; do
  echo "$elem"
done
```

We can store user input into an array with `read -a` , with a split on spaces.  
This is especially useful to store the output of a command into an array.

```shell
read -a my_arr                            # store user input into an array
read -a tokens < <(uptime)                # create an array of the tokens generated by the uptime command
```

Since Bash 4, the `readarray` and `mapfile` commands (2 identical commands) allow to convert input lines into elements of an array.  
For example, we can give it a file in output, and it generates an array variable with each of the file lines.

```shell
readarray -t my_arr < file.txt           # create an array of lines of the input file
                                         #  -t : remove the trailing new line
                                         #  -n 5 : limit the number of lines to read to 5 
                                         #  -0 5 : start including the array at a specific index (0 by default)
                                         #  -s 5 : discard the first 5 lines
```

### Associative Arrays (map)

Since Bash 4, associative arrays can be created with the `declare -A` command.  

```shell
declare -A my_map                   # declare a map
my_map["aaa"]="AAA"                 # assign a key/value pair in the map

my_map=(                            # syntax to declare and assign a map
  ["aaa"]="AAA"
  ["bbb"]="BBB"
)

echo "${my_map["aaa"]}"             # print the value for a key in a map
echo "${my_map[@]}"                 # print all values of a map (not the keys)
echo "${!my_map[@]}"                # print all keys of a map

[[ -v my_map["ccc"] ]]              # condition to test for the existence of a key in a map
```

## Signal Traps

When writing a Bash script that takes a while to run, we may want to react when signals are received.  
The `trap` command allows to define a function to use on reception of a SIGINT of SIGTERM signal.

```shell
# function to execute on signal reception
function teardown {
  echo "Teardown the script"
  exit 0
}

# set the signal trap
trap teardown SIGINT SIGTERM

# infinite loop
while true ; do
  sleep 1
done
```