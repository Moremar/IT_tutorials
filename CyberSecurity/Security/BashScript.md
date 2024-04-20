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
