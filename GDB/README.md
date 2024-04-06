# GNU Debugger (GDB)


## Role

GDB is a debugger to inspect a program state while it is running.  
It supports multiple languages, including C, C++, Rust, Ada, Assembly, ...


## Installation

```shell
sudo apt install gdb       # Debian-based Linux (Ubuntu)
sudo dnf install gdb       # RedHat-based Linux (CentOS Stream, RHEL, Fedora)
brew install gdb           # MacOS
```

## Usage

GDB can run only on binaries that have been compiled with debug symbols.  
Debug symbols are all the information about the source code not used once compiled, like variable names, C instructions...  
With gcc ang g++ compilers, debug symbols can be included with the `-g` option.  

```shell
gcc -g -o invalid invalid.c
```

We can then launch the GDB debugger :
```shell
sudo gdb ./invalid
```

We can run GDB commands inside the GDB CLI to navigate in the execution.
```shell
   start                      # start the execution and set an implicit breakpoint at the first meaningful line
   run                        # start the execution until a breakpoint or the end of the program
   next                       # go to the next C instruction (short version : n)
   nexti                      # go to the next assembly instruction
   step                       # step into the function call at this instruction  (short version : s)
   finish                     # step out of the current function and show return value (short version : fin)
   break file:line            # set a breakpoint at the a specific line of a file (short version : br)
   break 25 if a == 3         # set a conditional breakpoint
   continue                   # go to the next breakpoint
   info locals                # show the value of local variables
   info args                  # show arguments the function was called with
   print a                    # show the value of variable a
   watch a                    # monitor the value of variable a
   watch a > 10               # monitor an expression
   list                       # show 10 lines of codes around the current position
   where                      # display the call stack
   quit                       # exit execution
```

If we need to execute multiple times a sequence of instructions inside GDB, we can have GDB execute them :
```shell
sudo gdb -ex "break 26" -ex "run" -ex "info locals" ./invalid1
```

## Debug Example

When we compile `invalid.c` we have a bug that needs to be investigated.  
```shell
$>  gcc -o invalid invalid.c
$>  ./invalid
BUG 2
```

We can compile with debug symbols and run the binary with GDB :
```shell
$>  gcc -g -o invalid_debug invalid.c
$>  sudo gdb ./invalid_debug
```

The program is very short so we can just start from the beginning, go to every line and check the variables.  
We would use `start`, then `next` to go to the next line or `step` to enter inside the `max()` function.  

By reading the code we can have a feeling that the issue is in the `max()` function.  
If so, we can use `break 7` so set a breakpoint at the first instruction of this function (line 7).  
Then we can use `run` instead of `start` to reach the breakpoint directly.

At every step, we can run `info args` and `info locals` to see the function arguments and local variables.  
We would then notice that when entering the `max()` function the second time, `result` still has value 100.  
This variable is not properly initialized in the function, so it initially has the value it had at the end of the last call.

Note that this simple bug would have been detected if we compiled with the `-W` or `-Wall` flags.