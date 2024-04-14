# Bash Scripts


## Introduction

Bash (Bourne Again Shell) is both an interactive shell and a scripting language for Unix systems.  
It can be used to automate tasks instead of using an additional scripting language like Python.  
It is recommended to not use Bash for scripts longer than 100 lines of code (beyond that, use Python).

Every Bash command that we can run in the terminal can be used in a Bash script.  
A Bash script usually has the `.sh` extension, and users must have execute permission on it to run the script.  


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