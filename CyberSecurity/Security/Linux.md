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


- `tree <DIR>` : display a directory as a tree structure


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


- `diff <FILE> <FILE>` : show the different lines between 2 files


- `find <DIR>` : list files and folder matching filter conditions
  - `-type {f|d}` : list only files/directories
  - `-mtime -7` : filter on files/directories modified in the last 7 days
  - `-size +10M` : filter on files/directories bigger than 10M
  -  `-name result*` : filter on a regex on the file or directory name
  - `-delete` : delete the matching files/directories


- `cat <FILE>` : display the content of a file in the console


- `head <FILE>` / `tail <FILE>` : display the first/last 10 lines of a file or stdin in the console
  - `-n 5` : specify the number of lines to display
  - `-c 5` : specify the number of bytes to read instead


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
  - `tr ab km` : replace all 'a' by 'k' and all 'b' by 'm'
  - `tr -s ab km` : same as above
  - `tr a-z A-Z` : make a string upper-case
  - `tr -d ab` : delete all the 'a' and 'b' characters in the input
  - `tr -d [:alpha:]` : delete all letters, other selectors include `digit`, `alnum`, `lower`, `upper`...


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


- `sudo <CMD>` : run a command as superuser, require user password and the user must be allowed to use sudo


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

# we can store the result of a command as a temporary file provided to another command with <(CMD)
echo <(ls)                         # /dev/fd/11   (tmp file path)
diff <(ls ./dir1) <(ls ./dir2)     # diff between the file names of 2 folders

# we can also write it in the other direction with >(CMD)
# the 1st commands writes into a tmp file, and that file is the input of the 2nd command 
ls > >(echo)                      # /dev/fd/12
```


### Shell Expansion

Shell expansion is a group of transformations of the command performed by the Bash shell before executing it.

#### Globbing

Globbing is the replacement of wildcards patterns by files or paths :
- `*` : any combination of characters
- `?` : any single character
- `[0-9]` : range of characters
- `**` : any combination of characters and `/` representing a folder (may need to be enabled)

For example, the command `ls *.jpg` uses globbing.  
Bash replaces `*.jpg` by the list of matching files, for example `boat.jpg plane.jpg`.   
The `ls` command received the replaced input, and does not even know that globbing was used.  

Note : Globbing does not use regular expressions !  
It looks similar, but the syntax is different and more limited.

#### Tilde expansion

`~` gets replaced by the content of the `HOME` environment variable, usually `/home/<USERNAME>`.  
`~+` gets replaced by the content of the `PWD` environment variable.

#### Brace expansion

Brace expansion allows to specify a set of value to iterate on :
```shell
echo aaa.{txt,csv}          # aaa.txt aaa.csv
echo {a..z}.txt             # a.txt b.txt ... y.txt z.txt
```

#### Variable expansion

Environment variables can be expanded inside a command.  
`$` indicates to the shell to access a variable, and curly braces indicates the limits of the variable name.
```shell
echo $HOME
echo ${HOME}

echo ${#HOME}                            # number of bytes in a variable (same as characters for ASCII)
echo ${HOME:2:5}                         # substring of an env variable
echo ${HOME/<PATTERN>/<REPLACEMENT>}     # replace a pattern in an env variable (one occurrence)
echo ${HOME//<PATTERN>/<REPLACEMENT>}    # replace a pattern in an env variable (all occurrences)
```

#### Escape characters

Some characters that have a special meaning in Bash need to be escaped with a backslash to be printed.  
Including them inside single quotes would also work, since escaping is disabled in single quotes.  

```shell
echo \" \' \* \\
echo '"'
```

#### Command Substitution

Command substitution is the inclusion of the output of a command in another command with the `$(<CMD>)` syntax.  
An alternative syntax is to use backticks, but it is regarded as less readable.

```shell
echo "Lines: $(ls | wc -l)"
echo "Lines:" `ls | wc -l`
```

#### Quotes in Bash

In Bash, unlike most programming languages, single quotes and double quotes do not indicate strings.  
They are simply used to control the type of shell expansion that Bash should perform.  
Single quotes disable word splitting, escaping and all shell expansion.  
Double quotes disable word splitting and some expansions (tilde, *, ?), but allow escaping and variable expansion.

```shell
echo $PWD/*.txt             # variable expansion and globbing : a.txt b.txt
echo "$PWD/*.txt"           # variable expansion only : /home/myuser/*.txt
echo '$PWD/*.txt'           # no shell expansion : $PWD/*.txt
```



### Environment Variables 

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
- `IFS` : characters used for word splitting, by default contains a space, a tab and a newline.  
  Single and double quotes disable word splitting, so we can create a file with spaces in its name : `touch "a b c.txt"`



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
echo -e "\e[1;3;32mHELLO\e[0m"     # green bold italic text, then reset style 
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


### Startup scripts

When a bash is started, a startup script is executed to load some configuration.  
Startup scripts usually initialize environment variables, aliases and run initialization scripts.

There are several startup scripts that are loaded in different situations :
- _~/.bashrc_ : loaded in an interactive non-login shell (like when opening a terminal on a linux machine)
- _~/.bash_profile_ : loaded in an interactive login shell (like SSH)
  - it often sources _~/.bashrc_ to have shared setup between login and non-login shell
- _~/.bash_login_ : loaded in an interactive login shell if _~/.bash_profile_ not found
- ~/.profile : loaded in an interactive login shell if _~/.bash_profile_ and _~/.bash_login_ not found


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

On MacOS, the shell used by the Terminal application is **ZSH**, not Bash.  
We can run the `bash` command to run Bash, but it runs on an old version (3.2) because of licensing issue.  
We can use the Homebrew package manager to install the latest Bash version.

```shell
brew update                 # update the list of packages that can be upgraded
brew upgrade                # upgrade the packages that can be upgraded
brew install <PKG>          # install a package (for example bash)
```

## Unix File-system Hierarchy Standard (FHS)

|      Folder     |     Usage     |
|:---------------:|---------------|
|       /         | root directory, parent of all top-level directories |
|     /bin        | essential binaries needed for boot before the _/usr_ partition is mounted<br/> → cat, ps, zsh ...<br/> → recent distributions use a symlink to `/usr/bin` |
|     /boot       | important files needed while booting (kernel files, bootloader files...) |
|     /dev        | device access files, for example `/dev/input/mice` for the mouse input |
|     /etc        | configuration files (mostly in .conf) |
|     /home       | home directories of users |
|     /lib        | libraries essential for binaries on the system<br/> → recent distributions use a symlink to `/usr/lib` | |
|  /lost+found    | directory where Unix stores files recovered during the repair of a corrupted file system |
|    /media       | mount points for removable storage media (like USB, SD card...)<br/> → shown in the left of the file browser GUI |
|     /mnt        | mount points for additional file systems |
|     /opt        | optional software packages installed by users<br/> → used by Homebrew to install its packages on MacOS |
|     /proc       | information about the OS, the kernel and running processes<br/> → `/proc/cpuinfo` : CPU model, frequency, cache...<br/> → `/proc/meminfo` : system memory...<br/> → `/proc/version` : Linux/OS/GNU version<br/> → `/proc/uptime` : time the system has been running<br/> → `/proc/loadavg` : average load for the past 1, 5 and 15 min | 
|     /root       | home directory of the root user |
|     /run        | run-time data that are discarded at shutdown or boot |
|     /sbin       | essential binaries for system management requiring root privilege<br/> → ifconfig, route, systemd ... |
|     /srv        | data used by services, for example an FTP server |
|     /sys        | information about the system, kernel and drivers |
|     /tmp        | temporary files for users and system, usually deleted on reboot |
|     /usr        | shareable read-only data<br/> → binaries, libs, source code, documentation... |
|   /usr/bin      | primary directory for executables shared among users<br/> → diff, du, scp ... |
|   /usr/sbin     | same for system management binaries requiring root privilege<br/> → chown, tcpdump ... |
|   /usr/local    | read-only files not meant to be shared with other machines<br/> → proprietary software... |
| /usr/local/bin  |  binaries local to the current user, that do not get managed by system packages<br/> → python3, wget, git ... |
| /usr/local/sbin | binaries locally installed for system administrators requiring root privilege<br/> → wireshark, nmap ... |
|     /var        | constantly changing data, potentially that need a backup<br/> → log files, emails, database, website in `/var/www/` ... |


## Files in Linux

In Unix philosophy, almost everything is represented as files.

A file in Linux references an **inode**.  
An inode contains all metadata of the file (type, size, permission, last access date...).  
It also stores the physical location where the file content is stored.  

The inode is stored in a reserved section of the file system, that can be checked with the `df -ih` command.  
Rows showing no info with this command indicate file systems that do not use inodes.  
If this inode section is full, we can no longer create files in the file system, even if there is free space for data.  

Directories are also files in Unix world, they are represented in a similar way, and also reference an inode.  
The inode stores similar metadata, and the list of files inside the folder.

The Unix file type of any file is shown by the `ls` command, it can be :
- `-` : normal file (txt, pdf, py ...)
- `d` : directory
- `l` : symbolic link
- `c` : character device
- `b` : block device
- `p` : named pipe
- `s` : socket


### Symbolic Links and Hard links

#### Symbolic Links

A symlink is a reference to another destination (file or directory).  
It is a file that has its own inode, and its storage area points to the same one as the referenced file.  
A file content can be modified via the referenced file name or via any symlink.   
If the referenced file is deleted, the symlink still exists and becomes dangling.  

```shell
ln -s <TARGET_FILE> <SYMLINK_FILE>          # create a symbolic link to a file
ln -s <TARGET_DIR> <SYMLINK_DIR>            # create a symbolic link to a directory
```

On Windows, a symlink (also called **soft-link**) can also be created in PowerShell.  
It is different from a Windows Shortcut : when looking at the content of the file (with `cat` for example), the symlink
shows the content of the original file, while the shortcut has a different content keeping the name of the reference file.
```shell
New-Item -ItemType SymbolicLink -Path <SYMLINK_FILE> -Target <REFERENCE_FILE> 
```

#### Hard Links

A hard link is a reference to an existing inode.  
The inode keeps track of how many hard links reference it (only 1 at original file creation).  
The inode is deleted if the last hard link referencing it is deleted.  
Because a hard link shares the same inode as the reference file, it obviously has the same file content.  

A hard link can be created only to a file, not a directory.  
A hard link can only reference a file on the same file system (unlike a symlink).  

Unlike a symlink that becomes dangling when the target file is removed, a hard link continues to reference the file.  
The file will only be removed when all hard links are deleted.  

A hard link is regarded by Unix as a normal file and has the `-` type.

Hard links are also created with the `ln` command, but without the `-s` option :
```shell
ln <TARGET_FILE> <HARD_LINK_FILE>
```

We can copy an entire folder with hard link instead of real file copy with the `-l` option.  
All directories are created (they cannot be hard-linked) but all files inside the directories are hard-linked.
```shell
cp -al <TARGET_DIR> <COPIED_DIR>
```

### Devices

Hardware devices connected to a Linux OS (mouse, keyboard, hard disk...) are represented as files.  
This allows to interact with them without knowing their technical details.  

Devices in Unix serve as interface between the OS and hardware/virtual components.  
Applications and users can interact with them by reading and writing from/to these device files.

**Character devices** offer unbuffered access to the hardware, allowing to read the stream byte by byte.  
**Block devices** offer buffered access to the hardware, bundling several bytes into blocks.  
**Pseudo devices** are devices not necessarily referring to a physical device.  

For example a hard-drive could be a block device under `/dev/sda`.  
Partitions of this hard-drive are pseudo-devices under `/dev/sda1`, `/dev/sda2` ...  

Terminal sessions are associated with a device, displayed with the `tty` command, for example `/dev/pts/0`.  
This allows communication between different terminal sessions for example by redirecting stdout to a terminal device.   

#### Pseudo-Devices

- `/dev/null` : discard the information written to it, always return EOF when written to.
- `/dev/random` : generate a stream of random bytes, we can get some random bytes with `head -c 5 /dev/random`
- `/dev/urandom` : similar to `/dev/random`, faster but less secure as it may re-use previously used environmental noise  
- `/dev/stdout` : standard output device associated with the specific terminal of the shell session
  - all commands have an implicit `> /dev/stdout` if no explicit redirection is specified
- `/dev/stdin` : standard input device associated with the specific terminal of the shell session
- `/dev/stderr` : standard error device associated with the specific terminal of the shell session



## Users, Groups and Permissions Management

### User Types

- **superuser (root)** : unrestricted access to the system
  - can add/remove users, install software, change system config...
  - only 1 root user on the system, with user ID = 0 
- **regular user** : users with configurable limited access
  - access to only their own files and directories
  - cannot perform admin tasks without permission
  - can obtain temporary root privilege with `sudo`
- **system user** : used by processes to run a background task (web server, build server, ...)
  - has no home directory

### User configuration

User information are stored over multiple files :
- `/etc/passwd` : contain username, user ID, primary group ID, user description, home directory, user shell ...
- `/etc/shadow` : encrypted user passwords and password aging information (requires root privilege)
- `/etc/group` : contain each group and all its member users

A user can be created with the `useradd <USERNAME>` command :
- `-m` : create a home directory for the user (only for non-system users)
- `-d` : specify a custom home directory
- `-s` : specify the user default shell
- `-g` : specify user primary group (by default one is created with the same name as the user)
- `-G` : specify a secondary group

The user password can be checked and monitored with the `passwd` command :
```shell
passwd -S                  # show current user username, password type, update time, days to expiration...
passwd                     # change password for the current user (prompt for the password)
sudo passwd -S user1       # show password info for a specific user
sudo passwd user1          # change password for a specific user

sudo passwd -l user1       # lock a user account
sudo passwd -u user1       # unlock a user account
sudo passwd -n 7 user1     # set a minimum password age (in days) for a specific user
sudo passwd -x 90 user1    # set a password expiration (in days) for a specific user
```

A user can be modified with the `usermod <USERNAME>` command.  
Note that changing the home directory or username can cause issues by invalidating all absolute paths.
- `-c` : change the user description (full name)
- `-s` : change the default shell
- `-g` : change the primary group
- `-d` : change the user home directory
- `-m` : move existing home directory to the new one
- `-l` : change username

A user can be deleted with the `userdel <USERNAME>` command.  
- `-r` : also delete the user home directory and mails
- `-f` : same as `-r`, also delete group with same name and forces deletion even if the user is logged in

### su and sudo

We can switch user using the `su <USERNAME>` command.  
This will request the password of the user to switch to.  
When used without a username, the `su` command switches to the `root` user.  
It is a good practice to prevent to log as the root user, by deleting and locking his password with `passwd -d -l root`.

`sudo` allows to run a specific command as the root user.  
It requires the user password, and the user must be explicitly allowed to perform the `sudo` command.  
The allowed sudoers are stored in the `/etc/sudoers` file.  

When a `sudo` command is executed and the user password is provided, a session is created for 15min.   
When this session is expired, the next `sudo` command will require again the user password.  
We can force the expiration of the session with `sudo -k`.  
We can start a shell in sudo mode with `sudo -s`, so all commands executed in it have an implicit sudo.

`sudo` can be used to execute a command as a different user by providing only our own password :
```shell
sudo -u user1 touch /home/user1/a.txt     # create a file in user1's home directory
```

#### sudo Configuration File

The sudo permissions are specified in the `/etc/sudoers` config file.  
It should never be edited directly, but with the `visudo` command that creates a temporary file and validates it before saving.  
We can specify on which host and which users and groups each user can sudo as. 
```shell
# General syntax for the sudo permissions
<USERNAME> <HOSTNAME>=(<USERS>:<GROUPS>) <COMMANDS>

user1 ALL=(ALL:ALL) ALL                 # give a user full sudo access
%group1 ALL=(ALL:ALL) ALL               # give a group full sudo access (use % to specify it is a group name)

user1 ALL= ALL                          # user1 can only sudo into the root user (not as other users or groups)
user1 ALL=(ALL:ALL) NOPASSWD: ALL       # user1 can sudo without entering his password
user1 ALL= NOPASSWD: /usr/bin/apt-get   # user1 can sudo into the root user with no password only to use apt-get
```

The `/etc/sudoers` file ends with the `@includedir /etc/sudoers.d` command.  
It includes all sudoers files under the _/etc/sudoers.d/_ folder as extensions of the original sudoers file.  
When adding sudo permissions for a user, it is a good practice to create a file for these permissions in that folder.  
Files in this folder are also created and edited with `sudo visudo /etc/sudoers.d/user1`

### Groups

Groups help to strengthen the system security by controlling access to files and directories.  
A group receives permissions, and users in that group inherit the group permissions.  
All users have a primary group, which is used for files and directories created by this user.  
Users can also have one or more additional groups.

The groups a user belong to can be printed with the `groups <USERNAME>` command.  
It indicates the groups listed in `/etc/group` for this user.

Default groups on Ubuntu :
- `root` : super-user group with full control over the system (only the root user is in it)
- `sudo` : members can use `sudo` for temporary privilege (sometimes called `wheel` on some distributions)
- `adm` : members can read log files under `/var/log/syslog`
- `lpadmin` : members can manage printers and print queues
- `www-data` : members have access to web content (used for web server processes)
- `plugdev` : members can manage pluggable devices (USB sticks, external HDDs...)

A group is created with the `sudo groupadd <GROUP_NAME>` command.
- `-g 5001` : create a new group with a custom group ID

A group is modified with the `sudo groupmod <GROUP_NAME>` command.
- `-n <NAME>` : change the group name
- `-g <ID>` : change the group ID 

A group can be deleted with `sudo groupdel <GROUP_NAME>` command.  
This does not delete the files owned by that group.

A user can be added/deleted to/from a group with the `usermod`, `adduser` and `deluser` command :
```shell
sudo usermod -G adm,plugdev user1      # set the additional groups to a specific user
sudo usermod -G plugdev user1          # remove a user from a group by overriding the additional groups

sudo adduser user1 adm                 # add a specific user to a group
sudo deluser user1 adm                 # delete a specific user from a group
```

### File Permissions

Every file and directory belongs to an owner, and to a group.  

Permissions on a file are :
- `r` (READ : 4) : list files in a directory or read file content
- `w` (WRITE : 2) : create/delete/modify a file or directory (also need EXECUTE for directories)
- `x` (EXECUTE : 1) : traverse a directory or execute a file

Permissions can be assigned for the 3 types of users :
- `u` (OWNER) : the user who owns the file
- `g` (GROUP) : the users in the group of the file
- `o` (OTHER) : other users

```shell
chmod g+r a.txt      # give READ access to member of the file group
chmod o-w a.txt      # remove WRITE access to other users
chmod 764 a.txt      # give rwx permissions to the owner, rw permissions to the group and r to other users
chmod 777 a.txt      # give rwx access to the owner, the group and other users
chmod 777 -R dirA/   # give rwx access to all users for all files and directories inside a directory

chown root:group1 a.txt      # change the owner and group of a file
chown root:group1 -R dirA/   # change the owner and group of all files and directories in a directory
```

New created files and directories have the owner and the group of the user who created them.  
Their permissions are decided by a base, from which we subtract the **umask**.  
By default, the base is `777` for directories and `666` for files.  
Common values for the umask are `022` and `002`.  
If we create a file with base `666` and umask `022`, its permissions will be `644`.

The umask can be modified in the current shell, or set in `~/.bashrc` to be persisted.  
To have it applied even in GUI sessions, we can modify its default value in the `/etc/logins.def` config file.  
The fields to edit are `UMASK` and `USERGROUPS_ENAB`.

#### Sticky Bit

By default, any user with write and execute permission in a directory can delete or rename files.  
Directories support a **sticky bit**, that prevents deletion and renaming for non-owner users.  
The sticky bit can be specified in the umask.  
The sticky bit has no effect anymore on files.  
The sticky bit is shown with `ls -l` at the position of the other users `x` permission.  
When the sticky bit is set, it shows `t` instead of `x` or `T` instead of `-`.  
The sticky bit is used for the `/tmp` directory, so every user can read and write but not delete other user's files.

```shell
umask             # show the umask
umask 022         # set the umask
umask 0022        # set the umask with a default sticky bit of 0

chmod +t a.txt       # set the sticky bit
chmod 1777 a.txt     # set permission and the sticky bit (see below)
```

#### SUID and SGID

**SUID** (Set User ID) is an advanced setting for a file, to allow it to run with more permission than the user running it.  
A file with SUID will be executed with the permissions of its owner (instead of those of the user running it).  

`ls -l` shows if the SUID bit is set for a file at the position of the owner `x` permission.  
When the SUID bit is set, it shows `s` instead of `x` or `S` instead of `-`.  

For example, `/usr/bin/sudo` has the SUID bit, so the sudo command has root permissions when any user runs it.  
When executed, the `sudo` binary asks for the password, checks if the user is an allowed sudoer, and only then it
executes the requested command.  
`su` and `mount` commands also use the SUID bit.

The SUID mechanism can be a serious security risk, and should be used only on compiled binary files, when absolutely needed.  
For example, if we set the SUID bit to the `python3` binary, it will allow any user to run any Python script as root !

**SGID** (Set Group ID) is similar to SUID, but the permissions of the group of the file are used at execution.  
It is displayed also by `ls -l` with a `s` or `S`, but at the position of the group `x` permission.  

```shell
chmod +s my_bin       # set the SUID bit
chmod g+s my_bin      # set the SGID bit
```
