# Linux


## Linux history 

Linux is an open-source, multi-tasking and multi-user Unix-like OS kernel serving as the foundation for many free and open-source OS.  
It was developed by Linus Torvalds in 1991 and runs on many servers, desktops, and embedded systems. 

The GNU project (GNU's Not Unix) initiated in 1983 aims at creating a free and open-source OS.  
Most GNU software are under the GPL licence (General Public Licence) promoting freedom of use, modify and delete the code.  
The Linux kernel is also released under the GPL licence.  
GNU provides a lot of the utilities used in combination with the Linux kernel.

GNU/Linux is the foundation of Unix-based OS.  
Unix used to proprietary and GNU/Linux is an open-source replacement for it.

Linux distributions are OS built from GNU/Linux and adding specific tools and software :
- Ubuntu : derived from Debian, designed to be user-friendly
- CentOS Stream : derived from RHEL (Red Hat Entreprise Linux) and offering frequent updates
- Kali Linux : designed for penetration testing and cyber-security
- RaspberryPi OS : optimized for the RaspberryPi single-board computer 


## Installation

Linux distributions can be run using a virtualization software like **Oracle VirtualBox**.  
Download the OS image from the Linux distribution website, and create a virtual machine running this image.

Once installed, we need to update the existing packages and install some additional tools.  
The commands to execute depends on the packet manager used by the Linux distribution.

##### Ubuntu
```bash
sudo apt update
sudo apt full-upgrade    # restart the VM if some kernel patches got installed
sudo apt install build-essential linux-headers-generic dkms
```

##### CentOS
```bash
sudo dnf update
sudo dnf install epel-release
sudo dnf update
sudo dnf install gcc kernel-devel kernel-headers make bzip2 perl
```

Some VirtualBox additions can then be installed to simplify the interaction with the host OS.  
From VirtualBox menu, click `Devices > Insert Guest Additions CD Image…`.  
This creates a virtual CD that we can open and run `VBoxLinuxAdditions.run` from a terminal.  

We can then enable : 
- clipboard sharing : `Devices > Shared Clipboard > Bidirectional`
- shared folder with the host : `Devices > Shared Folders > Shared Folders Settings > Add Share`

A VM can be saved as a **snapshot** with `Machine > Take Snapshot`.  
It creates a file saving the entire VM state, allowing to re-create the VM from the snapshot if needed.  


## Bash Shell

### Bash commands

- `echo <TEXT>` : Write the argument to the standard output
  - `-n` : no line break at the end
  - `-e` : allow escape sequences using backslash (\n, \t, colors, bold...)


- `pwd` : print the working directory


- `cd <DIR>` : move to a directory
  - `cd -` : move back to the previous directory
  - `cd ~` : move to the current user's home directory
  - `cd /` : move to the root directory
  - `cd ..` : move to the parent directory


- `ls <DIR>` : list the content of a directory
  - `-l` : detailed result (permission, owner/group, size, creation date)
  - `-t` : sort by modification time
  - `-r` : reverse the sort order
  - `-a` : include hidden files and directories
  - `-A` : same as `-a` but exclude implied `.` and `..`
  - `-h` : display the size in human-readable format (K/M/G)
  - `-S` : sort by file size
  - `--color={auto|always|never}` : use colors for the output


- `touch <FILE>` : create an empty file, or update the modification time if the file exists


- `mkdir <DIR>` : create an empty directory
  - `-p` : create parent directories if needed, and no error if the directory already exists


- `mv <SRC> <DEST>` : move and/or rename a file or directory


- `cp <SRC> <DEST>` : copy a file or directory
  - `-r` : recursive copy of a directory


- `rm <FILE>` : permanently remove a file or directory
  - `-r` : recursive removal of a directory
  - `-f` : do not ask for confirmation


- `rmdir <DIR>`: remove an empty directory


- `find <DIR>` : list files and folder matching filter conditions
  - `-type {f|d}` : list only files/directories
  - `-mtime -7` : filter on files/directories modified in the last 7 days
  - `-size +10M` : filter on files/directories bigger than 10M
  -  `-name result*` : filter on a regex on the file or directory name
  - `-delete` : delete the matching files/directories


- `cat <FILE>` : display the content of a file in the console


- `head <FILE>` / `tail <FILE>` : display the first/last 10 lines of a file or stdin in the console
  - `-n 5` : specify the number of lines to display


- `less <FILE>` : print a page of a text file (b/f to go one page backwards/forwards)
  - `b` : move backwards to the previous page
  - `f` : move forwards to the next page
  - `50p` : navigates to 50% of the text
  - `=` : display info about the current position
  - `-N` : show line numbers
  - `/hello` : look forwards for a string in the file
  - `?hello` : look backwards for a string in the file
  - `q` : quit the file


- `wc <FILE>` : count the number of lines, words and bytes
  - `-l` : only show the number of lines
  - `-w` : only show the number of words
  - `-c` : only show the number of bytes


- `du <FILE>` : display disk usage for a file or directory
  - `-s` : only show a summary
  - `-h` : human-readable units using K/M/G (by default it uses blocks)


- `nano <FILE>` : basic command-line text editor


- `sort <FILE>` : sort the content in a file (or from stdin)
  - `-r` : reverse the order
  - `-n` : sort according to numerical order
  - `-k 5` : sort according to the 5th column
  - `-u` : unique values (no duplicates)


- `uniq` : remove duplicate lines on a sorted input
  - `-d` : only keep the duplicates


- `grep <PATTERN> <FILE>` : looks for a pattern in a file or in stdin
  - `-F` : disable the basic regular expression and interpret the pattern as a fixed string
  - `-i` : case-insensitive matching
  - `-n` : show the line number of the match
  - `-r` : recursive search in sub-directories


- `tr <CHAR> <CHAR>` : replace a character by another in the input file or stream
  - `tr 'ab' 'km'` : replace all 'a' by 'k' and all 'b' by 'm'
  - `tr 'a-z' 'A-Z'` : make a string upper-case
  - `tr -d 'a'` : delete all the 'a' in the input


- `rev <STR>` : reverse a string


- `cut <FILE>` : extract from a file or stdin a part of the input
  - `-b 1-10` : bytes mode, extracts bytes 1 to 10
  - `-c 1-10` : characters mode, extract the characters 1 to 10
  - `-d ' ' -f 2` : field mode, use a space delimiter and extract the 2nd field


- `sed <FILE>` : run sed-specific commands on the input file or stdin (delete/insert/replace lines)
  - `s/hello/hi/g` to replace all occurrences of hello by hi
  

- `tee <FILE>` : send the output both to a file and to stdout (stream redirection allows only one of the 2)
  - `-a` to append instead of replacing the output file


- `which <CMD>` : show the full path of a shell command
  - `-a` : print all matching executables (not only the first)


- `ping <IP>` : send ICMP packet to an IP to test the connection


- `man <CMD>` : display the manual of a command


- `sudo <CMD>` : run a command as superuser


### Command Combination and Redirection

```shell
# execute multiple commands sequentially
echo AAA ; echo BBB

# streams
ls > output.txt        # redirect stdout to a file
ls 1> output.txt       # same but explicitly redirect stdout (stream 1)
ls >> output.txt       # append stdout to a file (instead of replacing)
ls 2> error.txt        # redirect stderr (stream 2)
ls 2> /dev/null        # discard stderr
ls 2>&1                # redirect stderr to stdout
ls < input.txt         # redirect stdin (stream 0)

# pipes
ls | wc -l

# we can redirect stderr to stdout if we want the next command to use it as input
ls invalid_file.txt 2>&1 > /dev/null | wc -l
```


### Globbing

Globbing is a transformation of the command performed by the Bash shell before executing it.  
It accepts a few special characters and syntax, that will be replaced.  
Globbed expression must not be between quotes (globbing is not performed on quoted strings).  

Valid globbing syntax :
- `*` : any combination of characters
- `?` : any single character
- `[0-9]` : range of characters
- `**` : any combination of characters and `/` representing a folder (may need to be enabled)

For example, the command `ls *.jpg` uses globbing.  
Bash replaces `*.jpg` by the list of matching files, for example `boat.jpg plane.jpg`.   
The `ls` command received the replaced input, and does not even know that globbing was used.  

Note : Globbing does not use regular expression !  
It looks similar, but the syntax is different and more limited.


### Shell environment 

Environment variables store configuration information and settings.    
They are written in upper-case, and can be used by programs running in the shell.

```shell
env                          # display all environment variables
echo "${PATH}"               # display the value of the PATH env variable
export MY_ENV=val            # define a new env variable in the current shell session
MY_ENV=val2                  # override an existing env variable
unset MY_ENV                 # remove an env variable 

MY_ENV=aaa <CMD>             # set an anv variable just for the execution of a command
```

Some common environment variables are :
- `HOME` : current user's home directory
- `USER` : current user's username
- `PWD` : current working directory
- `SHELL` : path of the default shell executable (not the current shell)
  - it can be changed with `chsh -s "/bin/bash"`
  - it can only pick options among shells registered under _/etc/shells_
- `TERM` : terminal type, modern terminals set it to `xterm-256color`
- `PS1` : prompt string of the shell, supporting placeholders :
  - `\u` : username
  - `\h` : hostname (up to the first dot)
  - `\H` : full hostname
  - `\w` : full working directory
  - `\W` : last folder of the working directory
  - `\t` : time (24h format)
  - `\@` : time (AM/PM format)


### Shell Colors and Style

Modern shells support 256 colors (see the `TERM` env variable) and multiple text styles.   
This formatting is specified using **escape sequences** in the strings to display.  
They are structured like `\e[<CODE>m` or `\e[<CODE>;<CODE>m` to combine multiple styles.  
`\e` or `\033` initiates an escape sequence.  
`[` indicates the start of the formatted string.  
`<CODE>` is an integer defining the style to apply.  
`m` indicates the end of the escape sequence.  

```shell
echo -e "\e[31mHELLO\e[0m"         # red text, then reset style
echo -e "\e[31;43mHELLO\e[0m"      # red text with yellow background, then reset style
echo -e "\e[1;3;32mHELLO\e[0m"     # green bold italic text, ten reset style 
```

|     Code     |     Style     |
|:---------------:|---------------|
| 0 | Normal style |
| 1 | Bold |
| 2 | Dim |
| 3 | Italic |
| 4 | Underlined |
| 5 | Blinking |
| 9 | Strike-through |
| 30 | Black foreground |
| 31 | Red foreground |
| 32 | Green foreground |
| 34 | Blue foreground |
| 40 | Black background |
| 41 | Red background |
| 42 | Green background |
| 44 | Blue background |

All available styles can be listed with the `infocmp` command.

These escape sequences are tedious to use and read, so the `tput` command can include them in a more readable way :
```shell
tput bold           # start the bold escape sequence, (equivalent to "\e[1m")
tput smul           # start underline sequence
tput setaf 4        # start foreground color 4 sequence
tput setab 4        # start background color 4 sequence
tput sgr0           # reset to default style
tput cup 5 20       # move the cursor by 5 vertically and 20 horizontally (used for in-shell GUI)
tput lines          # number of lines printable in the terminal
tput cols           # number of columns printable in the terminal
tput colors         # number of available colors
tput clear          # clear the terminal

echo -e "$(tput bold)$(tput setaf 1)Bob:$(tput sgr0) Hi"     # write "Bob:" in red bold, then reset style
```

Colors and styles can be used in the `PS1` env variable to customise the shell prompt string.  
In that case, escape sequences should be enclosed in `\[ ... \]` so Bash can exclude them from the string size calculation :
```shell
PS1="\[\e[1;32m\]\u@\h:\[\e[33m\]\W\[\e[0m\]$ "                            # with escape sequences
PS1="\[$(tput setaf 2)\]\u@\h:\[$(tput setaf 3)\]\W\[$(tput sgr0)\]$ "     # using tput
```

### Shell configuration

There are 2 ways to set configuration options in the shell :

- The `set` command is inherited from the original shell (sh).  
Features can be enabled with a `-` and disabled with a `+` prefix.
```shell
set -x          # xtrace mode : display every command executed by the shell (for debug)
```


- The `shopt` command is used to set Bash-specific configuration options.  
Features are enabled with `-s` and disabled with `-u`.  
```shell
shopt -s autocd      # allow to navigate to a folder without typing 'cd'
shopy -s cdspell     # allow minor typo in folder name when using 'cd' 
```

### Shell Aliases

Aliases allow to make a commonly used command shorter.  
An alias is only valid in the current shell session, and must be added to a startup script to be persistent.
```shell
alias ls='ls --color=auto'
alias g='grep -nr'
alias f='find . -name'
```

### Command Substitution

Command substitution is the inclusion of the output of a command in another command with the `$(<CMD>)` syntax.

```shell
echo "Lines: $(ls | wc -l)"
```

### Startup scripts

When a bash is started, a startup script is executed to load some configuration.  
Startup scripts usually initialize environment variables, aliases and run initialization scripts.

There are several startup scripts that are loaded in different situations :
- _~/.bashrc_ : loaded in an interactive non-login shell (like when opening a terminal on a linux machine)
- _~/.bash_profile_ : loaded in an interactive login shell (like SSH)
  - it often sources _~/.bashrc_ to have shared setup between login and non-login shell
- _~/.bash_login_ : loaded in an interactive login shell if _~/.bash_profile_ not found
- ~/.profile : loaded in an interactive login shell if _~/.bash_profile_ and _~/.bash_login_ not found

## Users

There are 3 types of users :
- **system user** : used by processes to run a background task (web server, build server, ...) and has no home directory
- **regular user** : access to only their own files and directories, cannot perform admin tasks without permission
- **superuser (root)** : unrestricted access to the system, can add/remove users, install software, change system config...


## Package Management

Linux distributions are shipped with a package manager that can centrally manage software installation and update.  
Debian-based distributions (like Ubuntu) use `apt`, and RHEL-based distributions (like CentOS Stream) use `dnf` (replacing `yum`).  
Many applications no longer need to include their own updater, since they get updated by the package manager.

The package manager needs to be run with administrative privileges.

##### Ubuntu

On Ubuntu, the list of available package versions is not automatically kept up-to-date by the `apt` package manager.  
It requires an `apt update` to refresh the local versions list.

```shell
sudo apt update             # update the list of packages that can be upgraded
sudo apt list --upgradable  # list packages that can be upgraded
sudo apt upgrade            # upgrade packages that can be upgraded (install additional dependencies if needed)
                            # packages that require the removal of other packages are not upgraded
sudo apt full-upgrade       # upgrade all packages, even those requiring to removing some existing packages

sudo apt install <PKG>      # install a package
sudo apt remove <PKG>       # remove a package
```

##### RHEL (Red-Hat Entreprise Linux)

On RHEL the list of available package versions is kept up-to-date by default, so `dnf` has no equivalent to `apt update`.  
EPEL (Extra Packages for Enterprise Linux) is a repository of additional packages for RHEL distributions.  
The `epel-release` can be installed via `dnf` to configure this repository to be used as a source for packages.

```shell
sudo dnf upgrade           # download the latest version of the package list and upgrade packages
sudo dnf update            # same effect (alias)

sudo dnf install <PKG>      # install a package (for example epel-release)
sudo dnf remove <PKG>       # remove a package
```

##### MacOS

On MacOS, rhe shell used by the Terminal application is **ZSH**, not Bash.  
We can run the `bash` command to run Bash, but it runs on an old version (3.2) because of licensing issue.  
We can use the Homebrew package manager to install the latest Bash version.

```shell
brew update                 # update the list of packages that can be upgraded
brew upgrade                # upgrade the packages that can be upgraded
brew install <PKG>          # install a package (for example bash)
```

## Folders in Linux

|      Folder     |     Usage     |
|:---------------:|---------------|
|     /root       | home directory of the root user |
|     /boot       | important files needed while booting (kernel files, bootloader files...) |
|     /etc        | configuration files (mostly in .conf) |
|     /dev        | device access files |
|     /opt        | optional software packages installed by users |
|     /lib        | libraries essential for binaries on the system |
|     /mnt        | mounted file systems |
|     /var        | constantly changing, like log files |
|     /bin        | essential binaries needed for boot before the _/usr_ partition is mounted<br/> → cat, ps, zsh ... |
|     /sbin       | essential binaries for system management requiring root privilege<br/> → ifconfig, route, systemd ... |
|   /usr/bin      | primary directory for executables shared among users<br/> → diff, du, scp ... |
|   /usr/sbin     | same for system management binaries requiring root privilege<br/> → chown, tcpdump ... |
| /usr/local/bin  |  binaries local to the current user, that do not get managed by system packages<br/> → python3, wget, git ... |
| /usr/local/sbin | binaries locally installed for system administrators requiring root privilege<br/> → wireshark, nmap ... |