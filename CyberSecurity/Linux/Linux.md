# Linux


## Linux history 

Linux is an open-source, multi-tasking and multi-user Unix-like OS kernel serving as the foundation for many free and open-source OS.  
It was developed by Linus Torvalds in 1991 and runs on many servers, desktops, and embedded systems. 

The GNU project (GNU's Not Unix) initiated in 1983 aims at creating a free and open-source OS.  
Most GNU software are under the GPL licence (General Public Licence) promoting freedom of use, modify and delete the code.  
The Linux kernel is also released under the GPL licence.  
GNU provides a lot of the utilities used in combination with the Linux kernel.

GNU/Linux is the foundation of Unix-based OS.  
Unix used to be proprietary and GNU/Linux is an open-source replacement for it.

Linux distributions are OS built from GNU/Linux and adding specific tools and software :

- **Red-Hat family** : distributions derived or influenced by RHEL, using RPM, SELinux and with extensive documentation
  - **Fedora** : community-driven, direct initiative from Red-Hat, cutting-edge technology, short release cycle and frequent updates
  - **CentOS Stream** : also direct initiative from Red-Hat, moderately cutting-edge (less than Fedora, more than RHEL)
  - **CentOS** : used to be the free downstream version of RHEL provided by Red-Hat, now deprecated
  - **RHEL (Red-Hat Enterprise Linux)** : targeted for business, with support and certifications, subscription required
  - **Rocky Linux** : downstream version of RHEL, open-source replacement of CentOS with 100% binary compatibility with RHEL
  - **Alma Linux** : similar to Rocky Linux, drop-in replacement for CentOS with long-term support and stability
  - **Oracle Linux** : similar to Rocky Linux, developed by Oracle and offering commercial support services (technical support, patches, updates...)


- **Debian family** : community-driven without a commercial entity driving it, using DPKG/APT
  - **Debian** : base of the entire family, offers multiple branches (experimental, unstable, testing, stable)
  - **Ubuntu** : based on Debian, user-friendly, release every 6m and LTS every 2y, developed by Canonical Ltd with community contribution 
    - **Ubuntu-Server** : variant of Ubuntu without a GUI (command-line only) used for servers 
    - **Kubuntu** : variant of Ubuntu using KDE as a desktop environment instead of Gnome 
    - **Xubuntu** : variant of Ubuntu using XFCE as a desktop environment instead of Gnome 
  - **Kali Linux** : based on Debian, designed for penetration testing and cyber-security 
  - **RaspberryPi OS** : based on Debian, optimized for the RaspberryPi single-board computer
  - **LinuxMint** : based on Debian or Ubuntu, comes with out-of-the box software


- **SUSE family Linux**
  - **SUSE Linux Enterprise (SLE)** : aims at businesses with LTS, commercially supported with subscription model 
  - **openSUSE** : free and open-source, community-driven, sponsored by SUSE Linux 
  - **openSUSE Tumbleweed** : rolling version of openSUSE with latest software (like Fedora for Red-Hat)
  - **openSUSE Leap** : more stable version than Tumbleweed (like CentOS for Red-Hat)


- **Others**
  - **ArchLinux** : rolling release model, always contains the latest software, use the pacman package manager, very customizable, manual steps to install 
  - **Gentoo** : highly customizable and flexible, use the Portage packet manager that compiles packages from source code, optimized for our CPU


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

Some VirtualBox additions can then be installed to improve the interaction with the host OS.  
From VirtualBox menu, click `Devices > Insert Guest Additions CD Image…`.  
This creates a virtual CD that we can open and run `VBoxLinuxAdditions.run` from a terminal.  

We can then enable : 
- clipboard sharing : `Devices > Shared Clipboard > Bidirectional`
- shared folder with the host : `Devices > Shared Folders > Shared Folders Settings > Add Share`

A VM can be saved as a **snapshot** with `Machine > Take Snapshot`.  
It creates a file saving the entire VM state, allowing to re-create the VM from the snapshot if needed.  


## Upgrade

`apt full-upgrade` upgrades installed packages, but not the Ubuntu OS version.  
If a new version of the Ubuntu OS is available, we can upgrade manually.  

There is a risk of data loss in case of upgrade failure, so we should have a full backup available.  
It is recommended to wait a few days after a new OS version release, so early patches can be released.

First ensure that all dependencies are updated, then reboot the system :
```shell
sudo apt update
sudo apt full-upgrade
sudo reboot
```
Ensure that the update manager is installed, we need it to perform the system upgrade :
```shell
sudo apt install update-manager-core
```
Execute the upgrade.  
Note that we first need to upgrade to the highest minor version, for example 22.04 to 22.10.  
We need to run again the same upgrade command to then upgrade from 22.10 to 23.04.
```shell
sudo do-release-upgrade
```

If we face some issues with the upgrade (bootloader, kernel...), we may need to use a **live Linux** for troubleshooting.  
A live Linux distribution is a Linux OS booted from DVD or USB, that does not save anything on disk (all is saved in memory).  
It allows access to the disk, so we can modify some files that could help with the boot.  
For example, we can modify the GRUB configuration file to show the bootloader menu and allow reboot on the previous OS version.


## Bash Shell


### Command Combination and Redirection

```shell
# execute multiple commands sequentially
echo AAA ; echo BBB

# streams
ls > out.txt           # redirect stdout to a file
ls 1> out.txt          # same but explicitly redirect stdout (stream 1)
ls >> out.txt          # append stdout to a file (instead of replacing)
ls 2> err.txt          # redirect stderr (stream 2)
ls 2> /dev/null        # discard stderr
ls 2>&1                # redirect stderr to stdout (stream 1)
                       # the operator is >& to redirect to a stream, 2>1 would redirect to a file called "1" !
ls > out.txt 2>&1      # redirect both stdout and stderr to the file out.txt
ls < in.txt            # redirect stdin (stream 0)

# <<< is used to pass a string as input to a command
input=$'line1\nline2\nline3'
while IFS= read -r line ; do
  echo "Processing line : $line"
done <<< "$input"                     # use a multi-line string as input for the while loop

# pipe : the first command is executed in the main shell, and the second in a subshell using its output as input
ls | wc -l

# we can redirect stderr to stdout if we want the next command to use it as input
ls invalid_file.txt 2>&1 > /dev/null | wc -l

# we can store the result of a command as a temporary file provided to another command with <(CMD)
# This is called "process substitution", <(CMD) creates a temporary file with the result of the CMD command.
echo <(ls)                         # /dev/fd/11   (tmp file path)
diff <(ls ./dir1) <(ls ./dir2)     # diff between the file names of 2 folders
wc -l < <(ls)                      # use the tmp file as standard input for the wc command

# we can also write it in the other direction with >(CMD)
# the 1st commands writes into a tmp file, and that file is the input of the 2nd command 
ls > >(echo)                      # /dev/fd/12
```

We can also group several command together, so they take a common input :
```shell
# execute several commands on the content of the input file
{
  read line1
  read line2
  echo "$line1 / $line2"
} < file.txt

# brackets variation, executing all commands in the group in a sub-shell instead of the main shell
(
  read line1
  read line2
  echo "$line1 / $line2"
) < file.txt
```


### Shell Expansion

Shell expansion is a group of transformations of the command performed by the Bash shell before executing it.

#### Globbing

Globbing is the replacement of wildcards patterns by files or paths :
- `*` : any combination of characters
- `?` : any single character
- `[0-9]` : range of characters
- `**` : any combination of characters and `/` representing a folder (may need to be enabled with `shopt -s globstar`)

For example, the command `ls *.jpg` uses globbing.  
Bash replaces `*.jpg` by the list of matching files, for example `boat.jpg plane.jpg`.   
The `ls` command received the replaced input, and does not even know that globbing was used.  

Note : Globbing does not use regular expressions !  
It looks similar, but the syntax is different and more limited.

#### Sequence expansion

Sequence expansion replaces a sequence by the list of elements between the start and end elements.
```shell
{1..5}              # 1 2 3 4 5
{1..10..2}          # 1 3 5 7 9  (step size 2)
{a..z}              # a b c ... y z
{z..a}              # z y ... c b a
file{1..3}          # file1 file2 file3
```

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
echo ${HOME#<PATTERN>}                   # remove the shortest match of the pattern
echo ${HOME##<PATTERN>}                  # remove the longest match of the pattern
echo ${HOME%<PATTERN>}                   # remove the shortest match of the pattern from the end of the string
echo ${HOME%%<PATTERN>}                  # remove the longest match of the pattern from the end of the string

file=aa.bb.txt
echo ${file#b*}            # aa.bb.txt : no change because aa.bb.txt does not match the pattern to remove "b*"
echo ${file#*b}            # b.txt     : the shortest match of the pattern "*b" is "aa.b" so it is removed
echo ${file##*b}           # .txt      : the longest match of the pattern "*b" is "aa.bb" so it is removed
echo ${file##*.}           # txt       : elegant way to get the extension of a file, we remove up to the last dot
echo ${file%*.}            # aa.bb     : elegant way to get the name of the file without the extension
echo ${file%%*.}           # aa        : the longest match of the pattern ".*" from the end is ".bb.txt" so it is removed
```

#### Escape characters

Some characters that have a special meaning in Bash need to be escaped with a backslash to be printed.  
Including them inside single quotes would also work, since escaping is disabled in single quotes.  

```shell
echo \" \' \* \\
echo '"'

# the -e option allows to interpret the special characters
echo "aa\nbb\ncc"       # print uninterpreted string "aa\nbb\ncc" (zsh would interpret \n)
echo -e "aa\nbb\ncc"    # print aa, bb and cc on 3 lines

# we can define a variable with the $'...' construct to interpret the characters
my_str=$'aa\nbb\ncc'
echo "$my_str"          # print aa, bb and cc on 3 lines
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
Double quotes disable word splitting and some expansions (tilde, *, ?), but allow escaping, variable expansion and command expansion.

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
- `PS3` : prompt string of the `select` control flow, usually overwritten in Bash scripts using a `select` loop
- `IFS` : characters used for word splitting, by default contains a space, a tab and a newline.  
  Single and double quotes disable word splitting, so we can create a file with spaces in its name : `touch "a b c.txt"`
- `RANDOM` : return a pseudo-random 16-bit integer (between 0 and 32767)


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
shopt -s autocd          # allow to navigate to a folder without typing 'cd'
shopt -s cdspell         # allow minor typo in folder name when using 'cd' 

shopt -s globstar        # allow the use of ** in globing to represent a recursive folder, for example folder1/folder2
shopt -s dotglob         # also include files starting with a dot (hidden files) in file expansion
shopt -s failglob        # fail the command on file expansion failure instead of returning the globbing pattern 
shopt -s nocaseglob      # case insensitive globbing matching
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
- _~/.profile_ : loaded in an interactive login shell if _~/.bash_profile_ and _~/.bash_login_ not found


### Z-Shell

Z-Shell (or zsh) is a Unix shell introduced in 1990 and is the main alternative to Bash.  
Most of the features and syntax are common with Bash, but Zsh offers additional features and options.

Zsh is the default Shell on several OS, like MacOS (due to licensing reasons), KaliLinux and ParrotOS.  
We can set Zsh as the default shell with the command : `chsh -s $(which zsh)`

It is common to use Zsh as the default shell, but use Bash for scripts, as it is more widely used.


#### Zsh configuration files

The first time we launch Zsh, if no Zsh startup scripts are detected, the Zsh configuration assistant is started.  
It can help with the configuration of those startup scripts, but we can use OhMyZsh instead.

Zsh configuration files are :
- `.zshenv` : loaded first in any Zsh shell, used for essential configuration like PATH, EDITOR...
- `.zprofile` : only loaded for login shells
- `.zshrc` : only loaded for interactive shells
- `.zlogin` : loaded last in login shells
- `.zlogout` : loaded in login shells when the user logs out

If we use Zsh only as an interactive shell and not for scripts, we can put all our config in `.zshrc`


#### Oh My Zsh

OhMyZsh is an open-source tool to improve the Zsh experience.  
When installed, it creates a `.zshrc` file with a lot of reasonable defaults.

OhMyZsh uses a system of plugins that can be loaded from the `.zshrc` file.  
These plugins offer better functionalities for specific tools, for example git, dnf, pip, docker ...

#### Some differences between Zsh and Bash

```shell
ls *.txt
```
Bash and Zsh behave differently on globing file expansion failure.  
If the folder does not contain any txt file, Bash displays the `*.txt` glob pattern.  
Zsh fails the command, acting like if the `globfail` shell option was set in Bash.

```shell
echo "Hello\nWorld"
```
Bash and Zsh behave differently for the special characters in the `echo` command.  
Bash displays `Hello\nWorld`, to get the `\n` interpreted as a newline we need `echo -e` or `$'Hello\nWorld'`   
Zsh interprets `\n` as a newline by default.

```shell
tasks=( task1 task2 task3 )
echo ${tasks[1]}
```
Bash and Zsh use a different indexing strategy for array variables.  
Bash returns `task2`, because in Bash array indices start from 0.  
Zsh returns `task1`, because in Zsh array indices start from 1.  
This difference would usually not impact us if we use Zsh interactively and keep writing scripts with Bash.


## Cron Jobs

`cron` is a command-line tool to schedule the execution of commands.  
cron is available on all Unix machines (Linux, Mac...).  
On Linux distributions using systemd, this can also be performed with systemd timers.

There are multiple implementations of cron, that have slightly different features (vixie-cron, anacron, cronie...).

The `crond` daemon process is in charge of running the scheduled processes.  
It reads the scheduled tasks from **crontab files** :
- `/var/spool/cron/crontabs` for user-level tasks, should be edited with the `crontab` command
- `/etc/crontab` for system-wide tasks (owned by root)
- `/etc/cron.d/` folder on Debian-based systems, used by third-party applications

User-specific cronjobs are created with `crontab -e` command that opens the corresponding crontab file.  
Active cronjobs are listed with the`crontab -l` command.

cronjobs are specified in the following format : `<MINUTE> <HOUR> <DAY> <MONTH> <DAY_OF_WEEK> <COMMAND>`  
We can use the `*` placeholder to execute the command at every value of a specific unit.

```shell
* * * * * ls                # run every minute
30 7 * * * ls               # run every day at 7:30
0,15,30,45 * * * * ls       # run every 15 min
0 8-19 * * * ls             # run every hour between 8am and 7pm
*/5 * * * * ls              # run every 5 min
```

cron can be configured to send the output of commands by email, with the `MAILTO` environment variable.  
It requires the installation of the `mailutils` package on Ubuntu.

cronjobs in `/etc/crontab` can be edited directly by the root user (using sudo).  
The syntax is slightly different, it has an additional parameter before the command to specify the user to run as.
```shell
* * * * * myuser cd /home/myuser/ && ls > ls.txt
```


## Package Management

Linux distributions are shipped with a package manager that can centrally manage software installation and update.  
Many applications no longer need to include their own updater, since they get updated by the package manager.  
The package manager ensures compatibility between installed software, and handles dependencies.

The package manager needs to be run with administrative privileges.

### Debian-based distributions (Ubuntu / Debian / Kali)

#### dpkg

dpkg (Debian Packet Manager) is the lowest-level package manager.  
It is used to install software as .deb files, a compressed archive with all files of the software.  
.deb files can be downloaded from the official Ubuntu package page : [https://packages.ubuntu.com/](https://packages.ubuntu.com/)  

dkpg does not handle dependencies.

```shell
sudo dpkg -i neofetch_7.1.0-3_all.deb                # install a .deb package (by .deb file name)
sudo dpkg -r neofetch                                # uninstall a package (by package name)
```

#### apt

apt builds on top of dpkg, it can download the requested packages from registered repositories and manage dependencies.  
`apt-get` is the older and more stable version of it, and both are compatible (they share config files and package format).  

The list of available package versions is not automatically kept up-to-date by the `apt` package manager.  
`apt` requires a `sudo apt update` to refresh the local versions list.  
It fetches from all central repositories the full list of available packages with their version.

System repositories are stored under `/etc/apt/sources.list`.  
Additional third-party repositories are stored under `/etc/apt/sources/lists.d/*`.

Repositories are defined with format `<type> <uri> <distribution> <domain1> <domain2> ...`.  
For example : `deb http://jp.archive.ubuntu.com/ubuntu/ jammy main restricted`
- type : either `deb` (binary packages) or `deb-src` (source packages)
- uri : address of the repository (or a mirror)
- distribution : ubuntu version to download package for
- component : define if free or paid, and if supported by Canonical (official) of by the Ubuntu community
  - `main` : official, free
  - `restricted` : official, paid
  - `universe` : community-supported, free 
  - `multiverse` : community supported, paid

We can add a **PPA** (Personal Package Archive), which is a repository from personal users for a specific project.  
The `add-apt-repository` command configures the additional repository and adds the public key of the repository to the trusted keys.

```shell
sudo apt update               # update the list of packages that can be upgraded
sudo apt list --upgradeable   # list packages that can be upgraded
sudo apt upgrade              # upgrade packages that can be upgraded (install additional dependencies if needed)
                              # packages that require the removal of other packages are not upgraded
sudo apt full-upgrade         # upgrade all packages, even those requiring to remove some existing packages
sudo apt autoremove           # remove old dependencies that are no longer needed

sudo apt install <PKG>        # install a package
sudo apt remove <PKG>         # remove a package

sudo apt show <PKG>           # display info about a package (size, dependencies, description...)

sudo apt install -f           # let apt resolve dependencies conflicts by installing/upgrading/removing dependencies

sudo apt add-apt-repository ppa:ondrej/php              # register a 3rd party repository
sudo apt add-apt-repository --remove ppa:ondrej/php     # deregister a 3rd party repository 
```

Integrity of files installed by apt can be checked with the `debsums` command :
- `-a` : run on all files managed by apt
- `-s` : silent mode, only log errors
- `-l` : list packages that do not have checksum info

Some useful packages to install are :
- `apache2` : HTTPD Apache web server
- `arp-scan` : host discovery tool on a local network using the ARP protocol
- `busybox` : binary combining tiny versions of many common Unix utilities
- `cmake` : cross-platform build system generator
- `cmatrix` : infinite program simulating the display from the Matrix in the terminal
- `debsums` : compare the checksum of deb packages with the ones stored in metadata to ensure they were not tampered with
- `dialog` : in-shell popup tool used in Bash scripts
- `firewalld` : popular Linux firewall on top of `iptables` or `nftables` backend
- `git` : most popular version control system for code and configuration files
- `gobuster` : enumeration tool for web URIs, DNS sub-domains, virtual hosts and AWS/GCP buckets
- `gparted` : Gnome Partition Editor GUI
- `htop` : interactive process viewer (improvement of top)
- `imagemagick` : image editor and image format convertor
- `john` : John the Ripper password cracking program
- `links` : in-terminal web browser (useful to see if a web server is reachable for example)
- `lvm2` : Logical Volume Manager to abstract multiple physical disks behind a single logical volume
- `neofetch` : system info script printing distribution logo and info on terminal
- `nmap` : network scanner (machines and open ports)
- `openssh-server` : SSH server to accept incoming SSH connections
- `screen` : terminal multiplexer, allowing the share of a single terminal by multiple processes
- `shellcheck` : Bash script validation tool
- `smartmontools` : SMART protocol support for physical drive health monitoring
- `terminator` : terminal program allowing to split the window horizontally and vertically into multiple consoles
- `wget` : command-line tool to download files from the Internet
- `wireshark` : networking traffic analyzer
- `zenity` : GUI popup tool used in Bash scripts
- `zsh` : advanced Unix shell (alternative to Bash)


### RHEL-based distributions (Fedora, CentOS, Red-Hat Enterprise Linux)

#### RPM (Red-Hat Package Manager)

RHEL-based distributions use the `rpm` low-level package manager.  
rpm can install, update and remove RPM packages, but it does not handle dependencies.

rpm can be used directly, but usually the `dnf` package manager is preferred.

```shell
rpm -p <PKG>.rpm              # verify a RPM package
rpm -i <PKG>.rpm              # install a RPM package
rpm -e <PKG>.rpm              # remove a RPM package
```

#### dnf

`dnf` is the high-level package manager for RHEL-based distributions (replacing `yum`).  
It uses `rpm` under the hood to manage RPM packages and their dependencies.

On RHEL the list of available package versions is kept up-to-date by default, so `dnf` has no equivalent to `apt update`.  

EPEL (Extra Packages for Enterprise Linux) is a repository of additional packages for RHEL distributions.  
It is a community project to make high-quality Fedora packages available to CentOS Stream and RHEL.    
The `epel-release` package can be installed via `dnf` to configure this repository to be used as a source for packages.

```shell
sudo dnf upgrade             # download the latest version of the package list and upgrade packages
sudo dnf update              # same effect (alias)

sudo dnf search <STR>        # search known packages for a given string

sudo dnf install <PKG>       # install a package (for example epel-release)
sudo dnf remove <PKG>        # remove a package

sudo dnf mark install <PKG>  # mark an installed dependency so it is not removed even if the package
                             # that installed it gets removed

sudo dnf repoquery --provides <PKG>        # show the functionalities provided by a package
sudo dnf repoquery --requires <PKG>        # show the required dependencies of a package
sudo dnf repoquery --recommends <PKG>      # show the recommended dependencies of a package
sudo dnf repoquery --suggests <PKG>        # show the suggested dependencies of a package
sudo dnf repoquery --whatprovides <FN>     # show which packages provide a given functionality
sudo dnf repoquery --whatrequires <FN>     # show which packages depend on a given functionality
sudo dnf repoquery --whatsupplements <FN>  # show which packages improve a given functionality

sudo dnf deplist <PKG>                     # summary of dependencies of a package and what packages provide them

sudo dnf install epel-release              # 2 commands needed to make EPEL repos available
sudo dnf config-manager --set-enabled crb  # CentOS-specific
```

By default, when installing a package, dnf installs the required dependencies, and the recommended ones if they do not create a conflict.  
It does not install the suggested dependencies.

We can configure the repositories that dnf can access by adding repo files under `/etc/yum.repos.d/*.repo`.  
It already contains a `centos.repo` file by default.  
When installing `epel-release`, it adds some EPEL-related repo files here as well.

dnf uses **modules** to allow better control on the version of the software we use.  
A module is a set of related packages working together for a given functionality.  
Each module supports one or more versions, called **streams**.
```shell
dnf module list                  # list available modules

dnf module install nodejs        # install a module directly
dnf module install nodejs:18     # install a module directly on a specific version (stream)

dnf module enable nodejs         # enable a module
dnf module enable nodejs:18      # enable a module on a specific stream (version)
dnf upgrade                      # upgrade node to the version of the specified stream

dnf module remove --all nodejs   # uninstall all software installed as part of a module
dnf module disable nodejs        # disable a module, so it remains installed but we no longer get updates 
```


### Snap

Snap is an alternative package manager that tries to solve common issues with traditional package managers (`apt` or `dnf`).

Snap bundles each package with its dependencies, so it is no longer possible to have dependencies conflicts.  
The trade-off is that the same dependency can be installed multiple times (once for each package using it).  
This also allows Snap to use packages independent of the Linux distribution.

Snap packages are available on [https://snapcraft.io/](https://snapcraft.io/).  
It is branded as the app store for Linux, and is mostly used for desktop applications : Spotify, Steam, GIMP, JetBrains IDEs, ...

Snap packages are updated automatically by the `snapd` background process.  
Snaps are stored under `/var/lib/snapd/snaps/`, and they are simply replaced by the new version on update.  
These snap packages are mounted to `/snap/`, where they have a full file hierarchy with binaries and dependencies.  
Symlinks to the main binaries of the installed snaps are saved under `/snap/bin` that is part of the PATH.

```shell
sudo snap install gimp
```

### MacOS

On MacOS, the shell used by the Terminal application is **ZSH**, not Bash.  
We can run the `bash` command to run Bash, but it runs on an old version (3.2) because of licensing issue.  

We can use the **Homebrew** package manager to install the latest Bash version.

```shell
brew update                 # update the list of packages that can be upgraded
brew upgrade                # upgrade the packages that can be upgraded
brew upgrade <PKG>          # upgrade a specific package
brew install <PKG>          # install a package (for example bash)

brew list                   # list all installed packages
brew outdated               # list all outdated installed packages
```

## Unix File-system Hierarchy Standard (FHS)

|      Folder     |     Usage     |
|:---------------:|---------------|
|       /         | root directory, parent of all top-level directories |
|     /bin        | essential binaries needed for boot before the _/usr_ partition is mounted<br/> → cat, ps, zsh ...<br/> → recent distributions use a symlink to `/usr/bin` |
|     /boot       | important files needed while booting (kernel files, bootloader files...) |
|     /dev        | device access files, for example `/dev/input/mice` for the mouse input |
|     /etc        | configuration files (mostly in .conf)<br/> → `/etc/hosts` : locally configured DNS cache<br/> → `/etc/hostname` : set the hostname of the machine |
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
- `/etc/passwd` : contain username, user ID, primary group ID, user description, home directory, user shell ... (not the password!)
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
sudo passwd -d user1       # remove the password for user1 from /etc/shadow, disabling password-based authentication
                           # this is often done on the root user to prevent login as root (use sudo instead)

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

When a `sudo` command is executed and the user password is provided, a session is created for 15 min.   
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

chown root:group1 a.txt      # change the owner and group of a file (need to be the file owner or root)
chown root:group1 -R dirA/   # change the owner and group of all files and directories in a directory
```

#### Umask

New created files and directories have the owner and the group of the user who created them.  
Their permissions are decided by a base, from which we subtract the **umask**.  
By default, the base is `777` for directories and `666` for files.  
Common values for the umask are `022` and `002`.  
If we create a file with base `666` and umask `022`, its permissions will be `644`.

The umask can be modified in the current shell, or set in `~/.bashrc` to be persisted.  
To have it applied even in GUI sessions, we can modify its default value in the `/etc/logins.def` config file.  
The fields to edit are `UMASK` and `USERGROUPS_ENAB`.

```shell
umask             # show the umask
umask 022         # set the umask
```

#### Sticky Bit

By default, any user with write and execute permission in a directory can delete or rename files.  
Directories support a **sticky bit**, that limit file deletion and renaming to root, directory owner and file owner.  
The sticky bit can be specified in the umask.  
The sticky bit has no effect anymore on files.  
The sticky bit is shown with `ls -l` at the position of the other users `x` permission.  
When the sticky bit is set, it shows `t` instead of `x` or `T` instead of `-`.  
The sticky bit is used for the `/tmp` directory, so every user can read and write but not delete other user's files.

```shell
umask 0022              # set the umask with a default sticky bit of 0

chmod +t mydir          # set the sticky bit
chmod 1777 mydir        # set permission and the sticky bit (see below)
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

The `/bin/passwd` command used to modify the password of the current user also has the SUID bit.  
It is required, because it needs to modify the user password hash in `/etc/shadow` that is only writable by root.

The SUID mechanism can be a serious security risk, and should be used only on compiled binary files, when absolutely needed.  
For example, if we set the SUID bit to the `python3` binary, it will allow any user to run any Python script as root !

**SGID** (Set Group ID) is similar to SUID, but the permissions of the group of the file are used at execution.  
It is displayed also by `ls -l` with a `s` or `S`, but at the position of the group `x` permission.  

```shell
chmod +s my_bin       # set the SUID bit
chmod g+s my_bin      # set the SGID bit
```

## Linux Processes

A process is an independent execution unit managed by the Linux kernel.  
It has its own resources (CPU, memory, opened files, network connections...) that it does not share with other processes.  

When a process in a shell exits, its exit code is available via the `$?` special variable, with `echo $?`.  
The exit code is 0 on success, and any other value on failure (usually 1).


### Process monitoring 

Processes can be monitored from the **System Monitor** application in Ubuntu.  
Processes are organized in a hierarchy, where each process knows its parent process that initiated it.  
For example if we run `ping` in a bash, the bash is the parent process of the ping process.

#### ps command

Processes can be displayed with the `ps` command.

`ps` can use Unix-style parameters, with a dash prefix :
- `-e` or `-A` : show all running processes
- `-f` : full details, show additional columns like process owner, parent process ID, time, command...
- `-l` : long format, add a few more columns including the process state
- `-p 1234` : limit to a specific process ID
- `--forest` : show the process hierarchy

`ps` can also use BSD-style parameter with no dash prefix :
- `a` : show all processes of all users
- `u` : user-oriented output with additional columns
- `x` : also include processes without a tty (started outside a terminal)

```shell
ps                         # show running processes in the current terminal
ps -A                      # show all processes (same as -e)
ps -e -f -l                # show details about all processes
ps aux                     # show details about all running processes (BSD-style)
```

#### top / htop commands

The `top` command displays all processes from the system (in-shell equivalent of the System Monitor).

It uses individual process-level pseudo-files under `/proc` giving info on each process.  
Running it with `sudo` includes more processes that are not visible to our current user.  
- `-u <username>` : limit to processes owned by a specific user
- `-d 5` : set the delay between 2 updates to 5 sec
- `-i` : hide idle processes
- `-c` : show the full command line (instead of just command name)

When top is running, we can also perform some actions on the processes displayed :
- `F` (fields) : select fields to display, specify the sort field, ...
- `K` (kill) : send a signal to a process
- `R` (renice) : renice a process
- `Z` : switch on color mode

The `htop` command is an improved version of top.  
It needs to be installed with `sudo apt install htop` on Ubuntu.  
It has nice colors by default and shows CPU and memory usage, allows sorting by column on click and scrolling
to see the entire command...  
A few shortcuts are displayed at the bottom (search, filter, show as a tree, increase/decrease niceness, kill process).


### Process Priority

The operating system uses **context switching** to run multiple processes in parallel.  
It works a bit on a process, then moves to another, then to another, then back to the first...

We can influence the priority of a process by setting its **niceness** with the `nice` command.  
The niceness is a value between -20 (high priority) and +19 (low priority), with a default of 0.  
The nicer a process is, the more it lets other processes run.  
The scheduler will dedicate more time to processes with lower niceness.  
We need administrative privilege to decrease the niceness (higher priority) but not to increase it.

```shell
nice -n 19 ping google.com         # start a process with niceness 19

pgrep ping                         # get the process ID of the process running the ping command, for ex 1234
sudo renice -n 10 1234             # set the niceness of running process with PID 1234 to 10
```

### Signals

Signals are messages sent to running processes to interrupt the process flow at a convenient time.  
We can emit a signal, and the OS will deliver it to the running process asynchronously.

The `kill` command can send signals, that the OS will deliver to a process to interrupt it.

The most popular signal types are :
- **SIGTERM** (terminate) : tell the process to terminate if possible but allow it to clean up or ignore the signal
- **SIGINT** (interrupt) : tell the process to stop so we can regain control over the terminal (Ctrl-C)
- **SIGKILL** (kill) : kill the process without giving it a chance to cleanup or ignore the signal, handled by the kernel and the process does not even know about it
- **SIGHUP** (hang up) : notify a process that the terminal it runs in has been closed, so process should stop if not a daemon
- **SIGSTOP** (stop) : tell the kernel to pause the process (not kill), not catchable by the process itself
- **SIGCONT** (continue) : tell the kernel to resume a process that was previously stopped

```shell
kill -l                         # show all available signals and their ID

kill 1234                       # send a SIGTERM signal to process 1234 (default signal)
kill -s SIGTERM 1234            # explicitly send a SIGTERM signal
kill -SIGTERM 1234              # alternative syntax
kill -s 15 1234                 # send the SIGTERM signal by ID (as listed by kill -l)

kill -s SIGINT 1234             # send a SIGINT signal to process 1234

killall firefox                 # kill all processes for a given command name (also kill the sub-processes)
```

`kill` is a built-in Bash function, but there is also a `/usr/bin/kill` external binary.  
The built-in one is faster, but the external one may have more options and can be required when Bash built-ins are not usable (in scripts for example).

### Process State

A process state is shown with `ps -el` :
- `R` (running) : currently using CPU and memory
- `S` (sleeping) : waiting for an event or a signal
- `D` (uninterruptible sleep) : cannot receive a signal, used for system call (like I/O)
- `T` (traced or stopped) : when it receives a SIGSTOP or Ctrl-Z from a shell
- `Z` (zombie) : no longer running but an entry still exists is in the process table

### Jobs

A job is a wrapper above a command being executed.  
It can contain multiple processes, for example the command `cat a.txt | wc -l` generates a job that has 2 processes.  

A job can be run in the foreground (blocking the shell) or in the background with a `&` suffix.  
Jobs running in the background still display their output in the shell (if not redirected).

A job can also be run with `nohup`, to keep it running even when the shell session is closed.  
It will create a `nohup.out` file in the current directory for its output.  
When the shell is closed, the parent process of the process running with `nohub` becomes process 1 (systemd).

```shell
ping -c 10 google.com > a.txt &                 # run a job in the background
  [1] 1234                                      # display job ID and process ID
  [1] Done   ping -c 10 google.com > a.txt &    # display a message when the job is done

jobs                                            # list running jobs
fg                                              # bring the last started job to the foreground
fg %1                                           # bring job 1 in the foreground

CTR-Z                                           # pause the current job, it is set as Stopped in the jobs output
fg %1 &                                         # resume job 1 and run it in the background
bg %1                                           # same

kill %1                                         # send a SIGTERM signal to job 1 (only works with the builtin bash kill)
kill -s SIGKILL %1                              # send a SIGKILL signal to job 1

wait                                            # wait for all background jobs to complete
wait %1                                         # wait for background job 1 to complete
wait -n                                         # wait for any background job to complete

nohup ping -c 10 google.com > a.txt &           # start a job in the background that survives when closing the shell
```


## Boot Process and Systemd


### Bootloader

On computer startup, the first component to load is the BIOS / UEFI, in charge of loading the hardware itself.   

Then the bootloader is the first software to load on startup, and it is the first we can influence.  
It is in charge of loading the OS : it loads the kernel into memory, and then hands control to it.  
On Linux, the bootloader is **GRUB2** (Grand Unified Bootloader).  
On Windows machines, the bootloader is the **Windows Boot Manager**.  

On Linux, the bootloader config can be changed in the _/etc/default/grub_ configuration file.  
After modification, we should run `sudo update-grub` to update the GRUB configuration.  
It re-generates the final bootloader config file _/boot/grub/grub.cfg_ from this new config.  
For example, to force the GRUB menu to show on startup for 5 sec, we can modify :
```shell
# GRUB_TIMEOUT_STYLE=hidden             # comment this line out
GRUB_TIMEOUT=5
```
This can allow us to start the machine in recovery mode and get a root shell.


### Linux Kernel

The Linux kernel is the core component of the Linux operating system.  
It was created by Linus Torvalds and released in 1991.  

The kernel is responsible for managing system resources and coordinating processes :
- **process management** : schedule processes, allocate resources, inter-processes communication...
- **memory management** : manage physical and virtual memory, handle allocation and de-allocation
- **file system management** : support multiple file systems (ext4, xfs...), handle read and write on those
- **networking stack** : implementation of various network protocols (Ethernet, TCP/IP...), routing, packet filtering, traffic control
- **hardware abstraction layer** (HAL)

**Kernel modules** are pieces of code that can be loaded into the kernel to extend its functionalities.  
Some proprietary drivers can be loaded to the core of the OS using this module mechanism.  
Modules are often used for device drivers (Nvidia graphics card, wireless card), virtualBox add-ons, ZFS filesystem...  
We can list loaded kernel modules on our system with : `sudo lsmod` 

The Linux kernel is updated with the packet manager just like other packages.  
We can lock a specific version to prevent the kernel to be upgraded automatically.  
This is mostly used if we have installed custom modules, that are not compatible with later versions of the kernel.
```shell
sudo apt-mark hold linux-generic-hwe-22.04              // on Ubuntu
sudo dnf versionlock kernel                             // on CentOS
```

**Kernel mode** and **User mode** are 2 distinct privilege levels in an OS that decide the level of access a program has on the system resources.  
Kernel mode has unrestricted access, it is used by the kernel and by some device drivers.  
User mode has limited access to system resources, and is used by all other applications.    
These applications can perform system calls that the kernel receives and executes for the application if it has the required permission.


### Systemd

Systemd is a set of tools to manage processes, group them, start them automatically...  
There are a lot of different systemd processes : init, systemctl, journalctl, journald, networkd, logind...  
Most of these processes can be listed with : `ps -ef | grep systemd`

Systemd includes the `init` process, the main process of the OS (PID = 1) started directly by the kernel.  
It can be listed with the `ps 1` command, and its binary is stored under _/lib/sytemd/systemd_  
It is in charge of initializing basic functionalities of the OS.  
It becomes the new parent of any process that becomes orphan (for example a background process started in a shell when
the shell is closed).

Systemd has many roles :
- start the system
- mount drives
- start services
- configure network connections

Systemd created a controversy in the Linux community when it was introduced.  
It is criticized for being overly complex and doing too many things, violating the Unix philosophy.  
But it is widely adopted by several Linux distributions, and brings key advantages, like dynamic configuration,
improved speed using parallelization...


#### Systemd units

We can install and run a basic Apache web server with :
```shell
sudo apt install apache2               # install httpd web server
sudo apt install links                 # install links (in-terminal web browser)
links http://localhost                 # display the webpage delivered by the Apache web server
```
Simply installing the web server makes it available, and we can access the welcome page from a browser.  
We did not need to run manually a process to start the web server.

When installing apache2, it registered itself to Systemd as a unit, that we can monitor with `systemctl` :
```shell
systemctl list-units           # show all units registered in systemd
systemctl status <UNIT>        # show the status, the processes and the logs of a specific unit (for example apache2.service)

systemctl enable <UNIT>        # enable a unit, so it is loaded on boot if specified in the config file
                               # --now : also load it immediately
systemctl disable <UNIT>       # disable a unit so it no longer starts on boot                               
                               
systemctl start <UNIT>         # start a unit
systemctl stop <UNIT>          # stop a unit
systemctl restart <UNIT>       # restart a unit
systemctl reload <UNIT>        # reload the unit configuration

systemctl daemon-reload        # reload all service configurations (and remove remnants of old services)

systemctl cat <UNIT>           # show the configuration file of the unit
```

Multiple types of units can be managed by Systemd :
- **service** : define how a service should be started, stopped and managed 
- **socket** : represent a socket for inter-process communication or network services
- **device** : represent a device in the Linux device tree, to manage device-specific settings and dependencies 
- **mount** : represent a mount point for a file system
- **target** : represent a custom synchronization point for other units
- **slice** : represent a resource allocation group for system resources
- **timer** : represent a schedule to run an underlying service

#### Cgroups (Control Groups)

Cgroups are a feature of Linux kernel to group related processes together into a hierarchy.  
A web server for example can have multiple child processes to execute incoming requests.  
A cgroup can contain units or other cgroups.

We can limit the resources allowed to be used and measure resources used at cgroup level.  
When starting a sub-process, the sub-process is in the same cgroup as its parent.

The cgroup hierarchy can be viewed with `systemctl status` starting with the top level cgroup called `/`  
We can see the resources (CPU and memory) used by all cgroups with `systemd-cgtop [--depth=5]`  (optional depth, 3 by default)

#### Systemd Targets

A target in Systemd groups units logically towards a specific goal.  
```shell
systemctl get-default                      # display the default target (graphical.target)
systemctl set-default multi-user.target    # set another default target effective on reboot (no GUI, just a black terminal)
systemctl cat graphical.target             # display the config for a given target (config file location and content)
systemctl isolate multi-user.target        # switch target without rebooting
systemctl list-units --type target --all   # list all targets
```

#### Systemd Timers

Timers are a type of Systemd units letting us run a service at a later time.  
It operates on a disabled service, and should have the same name as the service with a `.timer` suffix.  
Timers can run a service once in the future or periodically according to a specified schedule.


#### Unit files

The unit files are the configuration files for the systemd units, for example _/lib/systemd/system/apache2.service_

A unit file contains a list of properties to define a specific unit.  
These properties are grouped in sections :
- `[Unit]` : common section to all types of units
  - `Description` : brief description of the unit
  - `Documentation` : URL of the documentation
  - `Requires` : other units to start before this unit (otherwise this one does not start)
  - `Wants` : other units to start before this unit (but still starts this one if failed)
  - `After` : other units not required, but if present this one should start after them
  - `Before` : other units not required, but if present this one should start before them


- `[Service]` : service-specific section to configure how the service is started, stopped, executed...
  - `Type` : process type deciding startup behavior : simple (default service behavior), forking, oneshot...
  - `ExecStart` : command to start the service, can include arguments and options (can appear multiple times if multiple commands to run)
  - `ExecStop` : optional command to stop the service, by default systemd sends a signal to stop it
  - `Restart` : when the service should be restarted (no, on-success, on-failure, always...)
  - `User` : user to run the service as
  - `Environment` : optional environment variables


- `[Install]` : section specifying if the unit should be enabled or not
  - `WantedBy` : targets that should include this unit as dependency.  
    Common targets are `multi-user.target` and `graphical.target`.  
    It enables the unit to be started at boot if `systemctl enable` was used for this unit.

To edit these unit config files, we should not edit them in `/lib/systemd/system/` because they may be overridden by later updates.  
Instead, we can copy them to `/etc/systemd/system/` and update this copy that takes precedence over the one in `/lib/systemd/system/`.  
After the change, we can call `sudo systemctl daemon-reload` to force the reload of modified services.  

These unit config files can also be edited with the `systemctl edit <UNIT>` command.  
It automatically creates a folder in `/etc/systemd/system/` to override only parts of the configuration.  
We can add another target in the `WantedBy` field for example.  
If we want to replace the `WantedBy` targets (instead of extending them) we need an empty assignment :
```
WantedBy=
WantedBy=graphical.target
```
This solution to edit is preferred as it allows setting only specific properties, and it is maintained by Systemd.


#### Systemd unit examples

##### Basic service limiting Firefox memory

To create a custom cgroup to limit the memory usable by firefox :
- create a Systemd user-level slice unit, by creating the file `~/.config/systemd/user/browser.slice` containing :
```shell
[Slice]
MemoryHigh=100M
```
- start the browser cgroup in systemd (it opens a firefox window) :
  `systemd-run --user --slice=browser.slice /usr/bin/firefox`
- We can monitor the memory usage from the System Monitor, it works on CentOS but in Ubuntu Firefox still uses more than 100M.  
  When right-clicking to access properties, we see that it runs in a different slice, created by snap.  
  When inspecting /usr/bin/firefox, we see it is not a binary but a text script calling /snap/bin/firefox  
  /snap/bin/firefox is just a symlink to /usr/bin/snap (that reads the original command to know it needs to start firefox)  
  We can see the real firefox binary used by snap by calling `ps -ef | grep firefox`  
  We can start again our systemd slice using this binary instead, and now Firefox is limited to 100M :  
  `systemd-run --user --slice=browser.slice /snap/firefox/3779/usr/lib/firefox/firefox`

##### Basic service starting at boot

- Create the service config file `/etc/systemd/system/myservice.service`.  
  This can be done either manually, or with : `systemctl edit --force --full myservice.service`
```shell
[Unit]
Description=Ping and log time
Requires=network-online.target
After=network-online.target

[Service]
Type=oneshot
StandardOutput=append:/var/log/myservice.txt
ExecStart=date '+%%T'
ExecStart=ping -c 3 facebook.com

[Install]
WantedBy=multi-user.target
```

- Start the service with `systemctl start myservice.service`  
  We can see that it was executed with `systemctl status myservice.service`  
  It shows status inactive, because it completed and exited.  

- We can enable the service so it is starts automatically on boot with `systemctl enable myservice.service`

##### Timer on the previous service

We first should disable the service with `systemctl disable myservice.service` to prevent it to start on boot.

Then we create the timer config file with `systemctl edit --force --full myservice.timer`

```shell
[Unit]
Description=Timer to start the custom service after 5 min

[Timer]
OnActiveSec=5min
Unit=myservice.service

[Install]
WantedBy=timers.target
```

The timer can be started like any unit : `systemctl start myservice.timer`

The timer can also be enabled so it is started on boot.

Timers can also be repeated according to a schedule with the `OnCalendar` property instead of `OnActiveSec`.  
The schedule can be defined either explicitly or using a shortcut like `hourly` or `minutely`.  
For example, to execute the underlying service every 15 min :
```shell
OnCalendar=*-*-* *:0,15,30,45
```

#### Journald

Journald is the tool in the Systemd suite in charge of centralizing system logs.  
It is a replacement for Syslog on Linux distributions.

Journald logs are stored in binary format to save storage space.  
Journald supports log file rotation and retention.

Journald also includes logs from the boot process.

`journalctl` is used to read the journald log files. 

```shell
journalctl                       # display all logs in all log files
journalctl -b                    # display all logs of the current boot
journalctl --list-boots          # display all available boots that have logs
journalctl -b <BOOT_ID>          # display all logs of a specific boot
journalctl -u apache2.service    # display all logs for a given unit
journalctl --since '2024-01-01'  # display all logs from a given date
journalctl --until '2024-01-01'  # display all logs until a given date
journalctl -f                    # display all logs and follow new logs
journalctl -t anacron            # display all logs with a specific identifier
```

Logs can be written to journald with the `systemd-cat` command :

```shell
echo 'Hello' | systemd-cat             # write a log to journald (visible with journalctl)
echo 'Hello' | systemd-cat -t aaa      # write a log to journald with a specific identifier
```


## Volumes and Mounts

### Partitioning

A partition is a part of a physical drive.  
Partitions each have their own size, name and file system, and cannot interact with each other.  
A common example is to have a partition per OS on a machine that has dual-boot configured.

A storage device (HDD, SSD, USB stick) is structured with a **partition table** :
- **MBR** (Master Boot Record) is the old partition scheme limited to 4 partitions and 2TB disk size
- **GPT** (GUID Partition Table) is the modern partition scheme limited to 128 partitions and much higher disk size

On Ubuntu, partitions can be edited with **GParted** (Gnome Partition Editor), installed with the `apt` package manager.

By default on Ubuntu, multiple partitions are created on the main disk `/dev/sda` :
- `/dev/sda1` for the bootloader in BIOS-based system
- `/dev/sda2` for the bootloader in UEFI-based system (fat32 file system)
- `/dev/sda3` for the Ubuntu OS (ext4 file system)

With VirtualBox, we can create a virtual disk for a virtual machine : _Settings > Storage > Controller: SATA > Add hard disk_  
After starting the machine, we can see in GParted that 2 disks are now available (`/dev/sda` and `/dev/sdb`).  
The newly created `/dev/sdb` disk has no partitions yet, it is fully unallocated.  
We can create a partition table with : _Device > Create Partition Table > gpt (partition table type)_  
Then we can create a new partition on the disk (specifying its size, name and file system).  
After clicking the Apply button, the newly created partition appears as `/dev/sdb1`.

Instead of using the GParted GUI to manage partitions, we can use the `parted` command-line tool.  
Running the `sudo parted` command opens the parted shell.  
```shell
help                             # show available commands
quit                             # quit the parted shell

print devices                    # show existing disks
select /dev/sdb                  # select a disk
print partitions                 # show existing partitions on the selected disk
rm 1                             # remove partition 1 on the selected disk
mklabel gpt                      # create a partition table on the selected disk (wipe all partitions on it)
mkpart primary ext4 2048s 1000   # create a partition with ext4 FS of 1GB
name 1 aaa                       # Give a name to partition 1 on the selected disk
```
All these parted CLI commands have an equivalent in the normal terminal, for example :
```shell
sudo parted /dev/sdb print partitions
```

When creating a partition with `parted`, we specified that the FS should be ext4, but we did not create the actual FS.  
To create the ext4 FS on the new partition, we need to run the following command (done automatically when using GParted).
```shell
sudo mkfs.ext4 /dev/sdb1
```

In general, we should prefer the GParted GUI when available.  
When working with a remote machine, we may not have access to a GUI so the parted CLI can be the only way.  
If we need to include parted commands in scripts, then the in-terminal commands can be considered.

To create an exFAT partition, we need to first create an NTFS partition with `parted` (it does not support exFAT) :
```shell
mkpart primary ntfs 2048s 1000   # create a partition with NTFS of 1GB
```
Then we quit the parted shell, install ubuntu exFAT packages, and install the exFAT FS on the partition :
```
sudo apt install exfat-fuse exfatprogs     # install exFAT packages
sudo mkfs.exfat /dev/sdb1                  # initialize the FS of the partition to exFAT
```
It then appears as using the exFAT FS in GParted as well.

### Volumes

A volume is a logical storage area on the system with a specific file system.  
A volume is usually associated with a single partition of a device, but it can sometimes contain multiple partitions (see LVM below).  
An OS can associate a drive letter (Windows) or a mount point (Linux) to a volume to make it accessible to users and applications.  

### Mounts

A mount point is a connection of a volume to the Linux directory tree.  
It makes the volume readable and writable for users and applications.  

Volumes from external removable medias are usually mounted as a sub-folder of the `/media` folder.  
In an Ubuntu virtual machine, that is where shared folders and VirtualBox add-on volumes are mounted.

Volumes from internal permanent disks are usually mounted as a sub-folder of the `/mnt` folder.  

Ubuntu can automatically create a volume on a partition we created and mount it.  
Ensure GParted is closed, then open the Files Browser and click "Other Locations".  
A folder should appear for the new partition, we can double-click on it, then right-click and select "Open Terminal".  
This automatically mounts the volume under `/media/<USER>/<LONG_ID>` under the `root` user and group.

We can create the volume and mount it manually for a better flexibility.  
We can see the partition names either with `parted` or with `lsblk -f` commands.  
```shell
mkdir /mnt/mybackups               # create a folder to mount the volume
mount /dev/sdb1 /mnt/mybackups     # mount the volume to that folder
                                   # -o <COMMA_SEPARATED_OPTIONS> to add mount options
                                   #   ro : read-only (even for root user)
                                   #   rw : read-write (default)
                                   #   noexec : prevent execution of any file in the volume
                                   #   nosuid : prevent the execution of files with the owner permission
                                   #   noatime : prevent update of the access time
                                   #   uid=1001 : set the user ID of the files (for exFAT that does not support users)
                                   #   gid=1001 : set the group ID of the files (for exFAT that does not support groups)     
                                   #   umask=0027 : set the permission umask (for exFAT that does not support permissions)     
mount                              # show all mounts. should list the newly mounted volume
df -h                              # also show all mounted volumes
umount /dev/sdb1                   # unmount the volume (using its partition name)
umount /mnt/mybackups              # unmount the volume (using its mounted folder)
```

#### /etc/fstab

The `/etc/fstab` file is a configuration file in Linux to define how storage devices and partitions should be mounted at boot.  
Each line in the file represents a volume to mount, and fields are separated by spaces or tabs :  

- device identifier (UUID given by `lsblk -f` or device path)
- mount point
- file system
- mount options (`defaults` for all defaults, `rw`, `nosuid`, `noexec`, `auto` to mount automatically, `nouser` to require root privilege...)
- dump options (backup utility, 0 for no backup)
- check order (0 for no check)

We can for example add this line to the `/etc/fstab` file to mount the /dev/sdb1 volume on boot :
```
UUID=d4f68760-eb33-4ce8-b3a8-194c3a6250d9 /mnt/backups ext4 defaults,noexec 0 0
```
The volume should be mounted at every boot, we can force it to mount now with `sudo mount -a`.

#### Mount an FTP volume

We can mount an FTP volume to a folder on our local machine, to use that remote folder as if it was local.  
On Ubuntu, this requires 2 additional packages :
```
sudo apt install fuse           # let the kernel know to delegate FS instructions instead of executing them itself
sudo apt install curlftpfs      # FTP FS support    
```
Then we can mount an FTP volume with :
```shell
sudo mkdir /mnt/ftp                                                     # create the folder to mount to
sudo curlftpfs ftp://<USER>:<PASSWORD>@<FTP_SERVER>/<FOLDER> /mnt/ftp   # mount the FTP folder to the local folder
sudo ls /mnt/ftp                                                        # check that we can access the FTP folder
sudo touch /mnt/ftp.test.txt                                            # create a file in the FTP folder

sudo fusermount -u /mnt/ftp                                             # unmount the FTP folder
```
Note that the user and password can be stored in the `/root/.netrc` file to avoid writing them in the command.

We can also specify this FTP mount in the `/etc/fstab` configuration file.  
The user and password can either be in the file or stored more securely in the `/root/.netrc` file.  
We need to specify `fuse` as the file system, so the kernel knows that it should delegate the FS operations to fuse.  
We need to specify the `noauto` option so the kernel does not try to mount it directly when the network is possibly not up yet.  
Instead we use the `x-systemd.automount` option, so systemd will mount it when it is first used.  
This results in a line like :
```shell
curlftpfs#ftp://<FTP_SERVER>/<FOLDER> /mnt/ftp fuse noauto,noexec,allow_user,ssl,x-systemd.automount 0 0
```

### Drive Health Monitoring

The SMART protocol can be used to monitor the health of the physical drives.  
It only reports on the physical drive, it does not catch errors at file-system or partition level.  
```shell
sudo apt install smartmontools
sudo smartctl --all /dev/sda
```
Note that this only applies to physical drives, virtual drives used with VirtualBox will show that SMART support is unavailable.

We can use `fsck` to check the health of a drive at file-system level.  
This requires the drive to not be encrypted, and to not be mounted (so the drive cannot be in use during the check).
```
fsck /dev/sdb1                         # should detect the file system and call internally fsck.ext4
fsck.ext4 /dev/sdb1                    # if the above does not work, call fsck.ext4 directly
```
If some errors are detected, `fsck` can try to repair the file system.  
It can make the volume mountable again, and the recovered files can be found in the `lost+found` folder.


### File System Resizing

Some file systems support resizing (like `ext4` on Linux), others do not (like `exFAT`).  
If a FS does not support resizing, we can simply mount it, copy its content somewhere else, delete the partition and create a new one.

To increase the size of a partition and its FS, we first need to increase the partition size, then the FS size.  
To decrease the size of a partition and its FS, we first need to decrease the FS size, then the partition size.

Example to decrease the size of partition `/dev/sdb2` and its ext4 FS :
```shell
umount /dev/sdb2          # unmount the FS before reducing its size
fsck /dev/sdb2            # good practice to check that the FS is healthy before reducing it
resize2fs /dev/sdb2 1G    # reduce an ext4 FS to 1G (each FS can have its own command, or simply not support it)
                          # this reduces the FS only, not the partition containing it !
                          # note that when increasing the FS size to the full partition size, we do not need to specify the size
```
This does reduce the FS size, but not the size of the partition containing it, so we can now resize the partition :
```shell
sudo parted                 # open the parted shell
    print devices           # show disks
    select /dev/sdb         # select a given disk
    unit GiB                # change the unit to GiB (base 1024 instead of base 1000 for GB)
    resize part 2 1         # reduce partition 2 on that disk to 1GiB 
```

### LVM (Logical Volume Manager)

Without LVM, partitions and FS sizes are limited by the size of the underlying disk.  
A partition is a part of the space on a specific disk, so its size cannot exceed the disk space.  

LVM is an abstraction on top of the physical disks, that allows to span partitions and FS over multiple physical disks.  
LVM combines the space on physical disks into a **volume group** that can be used to create mountable logical volumes.

LVM can be installed with : 
```shell
sudo apt install lvm2
```

#### Logical Volume Creation

To include a disk in a logical volume managed by LVM, we create a partition with 100% of space and set the `lvm` flag.  
We then create a physical volume in LVM referencing this partition.  
We can do that with multiple partitions, to have multiple physical volumes registered in LVM.  
We can then create a volume group across multiple physical volumes.
```shell
sudo parted                        # open the parted shell
    select /dev/sdb                # select the disk to create a partition for
    mklabel gpt                    # create a partition table for this disk
    mkpart primary 0% 100%         # create a partition using 100% of the disk
    set 1 lvm on                   # set the LVM flag for partition 1 (just created)
    quit                           # close the parted shell
    
sudo pvcreate /dev/sdb1            # initialize a physical volume for use in LVM (shows as "lvm pv" FS in GParted)
sudo pvs                           # list physical volumes known to LVM
sudo pvdisplay                     # detailed info about the physical volumes
sudo pvscan                        # force the detection of physical volumes if the above command did not detect them

# do above steps again for each other disk, for example /dev/sdc and /dev/sdd 

sudo vgcreate vgroup /dev/sdb1 /dev/sdc1 /dev/sdd1   # create a volume group "vgroup" with the 3 registered physical volumes
sudo vgs                                             # list volume groups known to LVM
sudo vgdisplay                                       # detailed info about the volume groups
sudo vgscan                                          # force the detection of volume groups if not automatically detected

sudo lvcreate -L 200M -n data1 vgroup       # create a logical volume of 200M in the "vgroup" volume group
sudo lvcreate -l 100%FREE -n data2 vgroup   # create a logical volume using all free space in the "vgroup" volume group
sudo lvs                                    # list all logical volumes known to LVM
sudo lvdisplay                              # detailed info about the logical volumes
sudo lvscan                                 # force the detection of logical volumes
```

Logical volumes can be used to create a file system and be mounted to folders as if they were partitions.  
They are referenced by their path listed by `lvdisplay`, for example `/dev/vgroup/data1`.

```shell
sudo mkfs.ext4 /dev/vgroup/data2              # create an ext4 FS on the logical volume
sudo mkdir /mnt/my_lvm                        # create a folder to mount the logical volume to
sudo mount /dev/vgroup/data2 /mnt/my_lvm      # mount the logical volume
```

#### LVM Modification and Deletion

```shell
# Add a physical volume to a volume group
sudo vgextend vgroup /dev/sde1

# Increase the size of a logical volume by 1G (require a free 1G in its volume group)
# the extension of the FS can be automated with the --resizefs option
sudo lvextend -L +1G --resizefs /dev/vgroup/data2

# Reduce the size of a logical volume
# This requires to unmount the file system first, then reduce the file system, then reduce the logical volume
sudo umount /mnt/my_lvm
sudo resize2fs /dev/vgroup/data2 800M
sudo lvreduce -L 800M /dev/vgroup/data2

# Remove a physical volume from a volume group
sudo pvmove /dev/sdb1              # tell LVM to move all data away from /dev/sdb1
                                   # this requires to have enough free space in the volume group of /dev/sdb1 to put
                                   # the data of /dev/sdb1 on other physical volumes in the group
sudo pvs                           # this should now show that /dev/sdb1 is fully free (ready to be removed)
sudo vgreduce vgroup /dev/sdb1     # remove physical volume /dev/sdb1 from its volume group
sudo pvremove /dev/sdb1            # remove the physical volume /dev/sdb1 from LVM

# Delete a logical volume and its volume group
sudo lvremove /dev/vgroup/data2
sudo vgremove vgroup
```

#### LVM Additional Features

LVM can be run on top of **software RAID** (0, 1, 5, 6...).  

LVM also supports **thin volumes**, which are volumes with total size bigger than the underlying physical volumes.  
This works fine as long as we do not actually need more storage than we have, and we can add more physical volumes later.

LVM supports **snapshots**, that mark the data at a given time.  
The snapshot itself does not use storage space, storage is only needed when data is changed after the snapshot.


## Networking in Linux

### ip

The `ip` command was recently added to replace the `ifconfig`, `route` and `netstat` commands.  
It provides information about the IP configuration, the routing table and the listening and established sockets.

```shell
ip addr show                                   # show network interfaces config : MAC address, IP address, network mask
ip addr add 192.168.1.4/24 dev enp0s5          # add an IP address to a network interface
ip addr del 192.168.1.4/24 dev enp0s5          # remove an IP address from a network interface

ip link set dev <interface> up                 # enable a network interface (listed by ip addr show)
ip link set dev <interface> down               # disable a network interface

ip route show                                         # show the routing table
ip route get 8.8.8.8                                  # show the route to a given IP address
ip route add 10.0.0.0/24 via 192.168.1.1 dev enp0s5   # add a route to the routing table
ip route add default via 192.168.1.1 dev enp0s5       # add a default route to the routing table
ip route del 10.0.0.0/24 via 192.168.1.1 dev enp0s5   # remove a route from the routing table 
```

`ip` is not available on MacOS, so we should use `ifconfig`, `route` and `netstat` commands instead.  
We can also install `iproute2mac`(with Homebrew) that offers a wrapper on these commands to use the `ip` syntax.


### iw

The `iw` command allows the management of the wireless interfaces.  

```shell
iw dev                              # list wireless interfaces : name, type, MAC address, configuration
iw dev wlan0 scan                   # scan for available wireless networks
iw dev wlan0 connect SSID_NAME      # connect to a wireless network
iw dev wlan0 disconnect             # disconnect from a wireless network
sudo iw link set dev wlan2 down     # shutdown a wireless interface, for example to change its type (up to restart)
iw dev wlan0 set type monitor       # change the interface type to monitor to capture traffic 
```

### DHCP

On Ubuntu, by default, the `systemd-networkd` service is in charge of DHCP.  
We can monitor its logs to understand its activity : `journalctl -b -u systemd-networkd`

NetworkManager is an alternative to `systemd-networkd` used by default on CentOS.  
We can monitor its logs with `journalctl -b -u NetworkManager`


### DNS

On Ubuntu, the `systemd-resolved` service is in charge of the DNS resolution.  
It listens to port 53 for incoming DNS requests, we can see it with : `lsof -i :53`

If we add some static DNS mapping to `/etc/hosts`, we need to refresh the local cache with :
```shell
sudo resolvectl flush-caches      # clear local cache and reload from /etc/hosts
sudo resolvectl status            # show the status (DNS server used for each interface)
sudo resolvectl statistics        # show how many DNS queries were replied, how many times the cache was used...
```


### SSH

To allow incoming SSH connections to a Linux machine, we need to run an SSH server.  
The most popular SSH server is **OpenSSH**, which is open-source, highly configurable and installed by default on Linux server distributions.  
An alternative is **DropBear-SSH**, a lightweight SSH server/client for environments with limited resources like embedded devices and IoT applications.  

```shell
sudo apt install openssh-server           # install OpenSSH and start a server as a Systemd service
sudo systemctl status ssh                 # check that the OpenSSH server is running

sudo ufw status                           # check if the firewall is active
sudo ufw allow ssh                        # create a rule to allow SSH through the firewall
sudo ufw enable                           # enable the firewall if it is disabled
```

When the SSH server is running, we can connect to it from another machine.  
If the SSH server has a public IP, it can be accessed from anywhere on the Internet, otherwise only from the internal network :
```shell
ping <SERVER>                 # ensure we can reach the machine (the IP is given by "ip addr show")
ssh <USERNAME>@<SERVER>       # open a remote shell on the Linux machine via SSH 
```

Access logs can be checked in `/var/log/auth.log` for suspicious activity.

We can customize the SSH server configuration in `/etc/ssh/sshd_config` (full option list with `man sshd_config`) :
- `Port 22` : can be changed to another port to avoid automated scans and bruteforce attempts
- `ListenAddress 0.0.0.0` : listen on all interfaces by default, we can limit it to a single network interface
- `LoginGraceTime 2m` : the time allowed for a user to enter his credentials
- `MaxAuthTries 6` : the number of attempts before the session is terminated
- `PermitRootLogin no` : to prevent root user to directly login through SSH (users would need to sudo from the server)
- `PubkeyAuthentication yes` : allow authentication with a private/public key pair
- `PasswordAuthentication no` : only accept login from users using a private/public key pair, not with a password
- `AllowUser myuser` : white-list some users
- `DenyUser myuser` : black-list some users
- `AllowGroup mygroup` : white-list all users in a group
- `DenyGroup mygroup` : black-list all users in a group

After modification of the SSH configuration, we should restart the SSH server :
```shell
sudo systemctl restart sshd
```

Permissions for SSH remote login require the user to have a local account on the server or to use a service directory.  
If the username on the SSH server is the same as the local machine, it does not need to be explicitly specified.

When a user first connects to an SSH server, he is asked to verify the host fingerprint (hash).  
Once verified, the fingerprint is added to the `~/.ssh/known_hosts` file.  
If we connect again later to this server, the fingerprint received from the server is compared to the known one.  
If they do not match, a warning is shown, as it could mean we are victim of a man-in-the-middle attack.

Instead of connecting to the remote server in SSH using a password, we can use a cryptographic key pair.  
The remote server needs to know the public key, and the user uses his private key to connect.  
When we create a key pair, we can optionally protect the private key with a passphrase, required at every use.  

```shell
ssh-keygen -t rsa -b 4096                      # generate a RSA key pair of size 4096 bits
                                               # private key :  ~/.ssh/id_rsa
                                               # public key :   ~/.ssh/id_rsa.pub

ssh-copy-id -i <PUBLIC_KEY> <USER>@<SERVER>    # copy the public key to the remote server in ~/.ssh/authorized_keys
                                               # this requires a password to access the server in SSH

ssh <USER>@<SERVER>                            # ensure that no password is required anymore
ssh <USER>@<SERVER> -i ~/.ssh/id_rsa           # specify the key to use (otherwise, all keys in ~/.ssh/ are tried)
```

Once the key pair is configured, we can disable the login via password.  
This reduces the attack surface, since a secret key is impossible to guess.  
It also forces an attacker to obtain the private key for login AND the user password for sudo.

By default, an SSH connection drops after a certain time of inactivity.  
To prevent this timeout, we can configure the client (or the server) to send keep-alive packets regularly.  
On client-side, we can configure it at user-level in `~/.ssh/config` or system-level in `/etc/ssh/ssh_config`.  

```shell
# for all hosts, send a keep-alive every minute and allow up to 3 successive failures
Host *
    ServerAliveInterval 60
    ServerAliveCount 3

# set the user that the SSH client should use for one specific host
Host 10.10.10.1
    User user1

# define a server nickname that we can use instead of the IP address
Host myserver
    Hostname 10.10.10.2
    User user1
```

When running an SSH client, parameters in the command have priority, then user-level config, then system-wide config.   

Many organizations allow SSH access from the outside only to a single host called **bastion** or **jumpbox**.  
That machine is hardened and is used as the entry point in the network, from where we can SSH to other internal machines.  
We can specify the bastion in the SSH client command, so both the keys for the bastion and the internal target server are stored locally (nothing in the bastion).
```shell
# specify a bastion to use as a jumpbox to reach the target server (so this command runs 2 SSH commands in a row)
ssh -J <USER>@<BASTION> <USER>@<SERVER>
```

The SSH client also supports local, remote and dynamic port binding :
```shell
# local port binding : local port 3333 redirects to remote port 3306 over SSH
ssh -L 3333:localhost:3306 <USER>@<SERVER>

# remote port binding (reverse tunnel) : the remote machine can use its port 3333 to reach our local machine on port 3306
ssh -R 3333:localhost:3306 <USER>@<SERVER>

# dynamic port binding : open a proxy on port 3000 (that a browser can use) that redirects to the remote server over SSH
ssh -D 3000 <USER>@<SERVER>
```

When SSH is configured between a client and a server, it also allows the use of SFTP.  
SFTP is used in the same way as FTP to transfer files between client and server, and is secured by SSH.  
Files can also be copied over SSH using the `scp` command :
```shell
scp <USERNAME>@<SERVER>:<FILE_TO_COPY> <LOCAL_DESTINATION>
```
Some GUI applications, like **WinSCP** or **CyberDuck** on Mac and Windows, allow the file transfer between a client and an SFTP server.


## Web Server using the LAMP Stack

### LAMP stack

The LAMP stack is a popular suite of technologies used to build a web server running on a Linux machine :
- Linux : Operating system
- Apache : open-source web server
- MySQL : relational database system maintained by Oracle since 2010
- MariaDB : alternative to MySQL, open-source fork from MySQL from the original developers who did not like Oracle policy 
- PHP : open-source scripting language well-suited for web development

It can be installed with :
```shell
sudo apt install apache2
sudo apt install mysql-server
sudo apt install mysql-client
sudo apt install php
sudo apt install libapache2-mod-php
```

### Apache Web Server

Apache web server (httpd) responds to HTTP requests from clients (browsers or applications).  
It is a **module-based system**, so modules can be used to extend its behavior (modify URL, use SSL, PHP support...).  
It supports **virtual hosts**, so a single httpd server can serve multiple websites. 

Installing the `apache2` package creates and starts the `apache2.service` unit in Systemd.  
The web server should already be running, and accessible at `http://localhost`.  
It starts multiple workers to respond to HTTP requests, that can be seen with `systemctl status apache2`.

The httpd server configuration is split into multiple configuration files, including one main file listing the others.  
The location of these files differs on CentOS and Ubuntu, on Ubuntu the files are : 
```shell
/etc/apache2/apache2.conf              # main configuration file
/etc/apache2/ports.conf                # defines ports the web server listens to (included in apache2.conf)
/etc/apache2/mods-enabled/*.conf       # config file for httpd modules (included in apache2.conf)
/etc/apache2/conf-enabled/*.conf       # config file for global httpd config (included in apache2.conf)
/etc/apache2/sites-enabled/*.conf      # config file for virtual hosts (included in apache2.conf)
```

Modules, global config and virtual hosts are created in the `/etc/apache2/*-available/` folders.  
To enable them in the web server, a symlink must be created in the corresponding `/etc/apache2/*-enabled/` folder :
```shell
sudo a2disconf charset            # disable the charset global config
sudo a2enconf charset             # enable the charset global config
sudo a2dismod alias               # disable the alias module
sudo a2enmod alias                # enable the alias module
sudo a2dissite 000-default        # disable the 000-default site
sudo a2ensite 000-default         # enable the 000-default site

sudo systemctl restart apache2    # after any config change, restart the httpd server
```

Multiple virtual hosts can be served by the same httpd server.  
This happens if the same machine has multiple hostnames, and each hostname corresponds to one website to serve.  
The server will decide which website to serve depending on the requested hostname.  

On Ubuntu, to create a new virtual site on a machine with hostname `ubuntu1`, we can :
- create a virtual site config file `/etc/apache2/sites-available/001-ubuntu1.conf` :
```shell
<VirtualHost *:80>
    ServerName ubuntu1
    ServerAdmin webmaster@localhost
    DocumentRoot /var/www/html/ubuntu1
    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
```
- create a symlink to it in `/etc/apache2/sites-enabled/` with the command `sudo a2ensite 001-ubuntu1`
- create the site root folder `/var/www/html/ubuntu1` and create a file `index.html` in it containing `Hello from ubuntu1 !`
- restart the httpd web server with command `sudo systemctl restart apache2`

With this configured, we should now get the custom welcome page when accessing `http://ubuntu1`.  
We should still get the default welcome page when accessing `http://localhost`.

We can also create a file called `.htaccess` in the document root folder or any of its sub-folders.  
This file can override the access policy at folder-level, to prevent Apache to serve it.  
For example this file can contain :
```shell
Deny from all
```
To be taken into account, we need to update the virtual host configuration in `/etc/apache2/sites-enabled/` to allow override :
```shell
<Directory /var/www/html/ubuntu1>
    AllowOverride All
</Directory>
```

We can use this feature to password-protect some folders inside the document root folder.  
We can create a password file `.htpasswd` in the same folder as the `.htaccess` file.  
This password file contains the hashed password for each user that has access.
```shell
sudo htpasswd -c .htpasswd user1      # prompt for a password for user1 and create the .htpasswd file with its hash
sudo htpasswd .htpasswd user2         # prompt for a password for user2 and update the .htpasswd file with its hash
```
The `.htaccess` file can then specify a restricted area that needs a user/password to access :
```shell
AuthType Basic
AuthName "Restricted Area"
Require valid-user
AuthUserFile /var/www/html/ubuntu1/.htpasswd
```

### PHP 

PHP is a commonly-used language for server-side scripting.  
Instead of requesting an HTML page, we request a PHP page that will run a script to customize the response.

On CentOS, PHP scripts are processed by a dedicated service `php-fpm.service`.  
On Ubuntu, the processing of the PHP script is handled by the httpd workers directly.  
It requires the `php8.1` httpd module (or higher) to be enabled.

We can create a sample PHP file called _phpinfo.php_ in `/var/www/html/` that contains the instruction `<?php phpinfo(); ?>`.  
When navigating to `http://localhost/phpinfo.php`, we can now see web server info : Linux version, server time, server version, env vars...


### MySQL

MySQL database is made of a MySQL server running the database, and some MySQL clients that interact with the database.  
A PHP worker uses a MySQL client to write or read the database.

On Ubuntu, the MySQL `mysql` service is enabled and runs upon install : `sudo systemctl status mysql`

By default on a new MySQL database, we can connect to the MySQL root user without a password if we have root privilege on the machine.  
```shell
sudo mysql -u root             # access the MySQL root user without password (require sudo for root privilege)
```
This opens a MySQL shell to the MySQL database, where we can use SQL commands :
```shell
CREATE DATABASE test;
USE test;
SELECT CURRENT_TIME();
CREATE TABLE student (student_id INT, first_name VARCHAR(255), last_name VARCHAR(255));
INSERT INTO student  (student_id, first_name, last_name) values (1, "Tom", "Riddle");
SELECT * FROM student;
```

In the MySQL shell, we create a user called `admin` and grant him full privileges :
```shell
CREATE USER 'admin'@'localhost' IDENTIFIED BY 'p4ssw0rd';
GRANT ALL PRIVILEGES ON *.* TO 'admin'@'localhost' WITH GRANT OPTION;
FLUSH PRIVILEGES;
```

We can now access the MySQL client with the `admin` user :
```shell
mysql -u admin -p              # prompt for the user password, no need for sudo
```

**PhpMyAdmin** is a free and open-source web-based administration tool for managing MySQL and MariaDB databases.  
We can install it with :
```shell
sudo apt install phpmyadmin
```
During the installation wizard, we select Apache2 (with Spacebar) to auto-generate the phpMyAdmin config.  
We can see that it created the file `/etc/apache2/conf-available/phpmyadmin.conf`.  
Once installed, we restart the web server with `sudo systemctl restart apache2`.  
We can then access the phpMyAdmin management interface at URL : `http://localhost/phpmyadmin`

To avoid the phpMyAdmin web interface to be compromised, we can add `Require local` in the config file to limit access to localhost connection.

We can create a new user and database in MySQL from the phpMyAdmin management interface for a WordPress blog.  
In phpMyAdmin, follow _New > User accounts > Add user account_.  
Create a user `blog` with Hostname `Local` to allow local socket connection from PHP to MySQL.  
Tick "Create database with same name and grant all privilege", then "Go" to create both the `blog` user and database.


### WordPress

WordPress is a free and open-source CMS (Content Management System) for blog and website creation.  
It is primarily based on PHP and MySQL, and is highly customizable with themes and plugins.

WordPress can be downloaded from [wordpress.org](https://wordpress.org/) (not [wordpress.com](https://wordpress.com/) that is a commercial company offering WordPress hosting).  
We can extract the zip and copy all its content to the document root folder configured to be served by our Apache site.  
For example, if we have set up Apache to serve files in document root `/var/www/html/ubuntu1` :
```shell
sudo rm /var/www/html/ubuntu1/*               # cleanup whatever already exists in the document root
sudo cp wordpress/* /var/www/html/ubuntu1/    # copy all content of the extracted wordpress archive to the document root
```

We can now access the WordPress setup screen in a browser at `http://ubuntu1/`, and click "Let's go".  
We can then enter the database name/host and username/password and press "OK".  
This will generate the content of the file `wp-config.php` to save ourselves in the document root folder.  
When done, click "Start Installation" in the browser.  
We can then choose the blog name and a new user that would be in charge of editing the blog (not a DB admin) and click "Install".  
The configuration is complete, we now have a WordPress blog that we can log into.


## Firewalld

The `ss` command  (recent replacement for the `netstat` command) shows information and statistics about network connections :
```shell
ss              # complete list of sockets with ESTABLISHED connection
                #  -l : complete list of LISTENING sockets
                #  -a : complete list of LISTENING and ESTABLISHED sockets
                #  -t : restrict to sockets using TCP
                #  -u : restrict to sockets using UDP
                #  -4 : restrict to sockets using IPv4 
                #  -6 : restrict to sockets using IPv6
                #  -n : show port number instead of protocol name
                #  -p : show the process info responsible for the socket
                              
ss -nap4        # list listening and established IPv4 sockets with their port ID and process details                               
```

The Linux firewall called `firewalld` controls which incoming and outgoing connections are allowed to go through.  

The firewall mechanism on Linux is made of multiple layers :
- the `netfilter` kernel subsystem, part of the Linux kernel in charge of packet filtering
- the firewalld backend, either `iptables` or its successor `nftables`
- the firewalld daemon service
- the firewalld tools like `firewall-cmd` (CLI) and `firewall-config` (GUI)

It is possible to interact directly with the firewall backend (iptables of nftables).  
Using firewalld tools provide an easier interface for firewall configuration.  

On CentOS and RHEL, `firewalld` is the default firewall and is already installed.  
On Ubuntu, the default firewall is `ufw` (Uncomplicated Firewall) that is easier but more basic than `firewalld`.

We can use the `firewall-cmd` tool to manage allowed connections :
- add `http` service if we run a web-server
- add `mdns` service if we need to be discovered by hostname

```shell
sudo ufw disable                                   # disable ufw firewall
sudo apt install firewalld                         # install firewalld
sudo systemctl enable --now firewalld              # start firewalld and enable it to start on boot

sudo firewall-cmd --state                          # show the firewall state (running / stopped)
sudo firewall-cmd --list-all                       # summary of configured rules
sudo firewall-cmd --get-services                   # show the list of services (protocol names) known to firewalld
                                                   # these names can be used instead of port numbers to allow/block traffic
                                                   # this mapping is ensured by an XML file per service under /etc/firewalld/services/
sudo firewall-cmd --info-service http              # show info about a specific service (port number and TCP/UDP)

sudo firewall-cmd --add-service=http               # allow a service by name until next reboot
sudo firewall-cmd --add-port=80/tcp                # allow a service by port number and protocol TCP/UDP until next reboot
sudo firewall-cmd --remove-service=http            # remove a service by name until next reboot
sudo firewall-cmd --remove-port=80/tcp             # remove a service by port number and protocol TCP/UDP until next reboot

sudo firewall-cmd --permanent --add-service=http   # use the --permanent option to change the permanent firewall config
sudo firewall-cmd --reload                         # reload permanent config
```

**Zones** in firewalld are groupings of network interfaces that are assigned a certain level of trust.  
A network interface can only be in one zone at a time.  
For example, a server can have 2 network interfaces : 
- one for internal network in the `trusted` zone allowing SSH
- one for public access in the `public` zone blocking SSH

Some built-in zone, from most trusted to least trusted, are : `trusted`, `home`, `work`, `public`, `drop`

Zones are stored as XML files under `/usr/lib/firewalld/zones/`
```shell
sudo firewall-cmd --get-zones
sudo firewall-cmd --get-default-zone
sudo firewall-cmd --set-default-zone=work
sudo firewall-cmd --zone=work --list-all                   # list all rules for a given zone
sudo firewall-cmd --zone=public --change-interface=enp0s5  # set an interface in a given zone
```
All previous commands can take the `--zone=ZONE` parameter, and use the default zone if not specified.



## Security-Enhanced Linux (SELinux)

SELinux is a security module for the Linux kernel developed by the NSA and made open-source.  
It allows using MAC in addition to DAC for access control policies, reducing vulnerability to privilege escalation.  

SELinux comes by default in the RH-based distributions (CentOS Stream, Fedora, RHEL...).  
It does not work on Ubuntu, that uses `AppArmor` instead (easier but less powerful than SELinux) with service `apparmor.service`.

DAC (Discretionary Access Control) defines access to resources based on the actor identity (owner, group, other).  
With DAC, when an application is compromised, the attacker gets access to all resources the application user can access.  
By using MAC in addition to DAC, SELinux mitigates the consequences of a compromise by adding another layer of security.  
For each access attempts, if DAC says OK, then MAC will check if the access should be granted.
```shell
sudo getenforce        # return "Enforcing" if running
sudo sestatus          # more info about SELinux status, including the current SELinux policy ("targeted" by default)
setenforce 0           # set to permissive mode (until next reboot)
```

Permanent SELinux configuration is stored in `/etc/selinux/config`.

### File Context

**File contexts** are a way of labeling files in SELinux, to check if access to specific files should be granted.  
Each resource has a SELinux user, role, type and label, shown with `ls -Z`.

```shell
ls -Z
   -rw-rw-rw-. user1 user1 unconfined_u:object_r:default_t:s0 test.txt    
```
- SELinux user : `unconfined_u`
- SELinux role : `object_r`
- SELinux type : `default_t`
- SELinux label : `s0`

These users, roles, types and label are used by SELinux rules to allow or deny access to resources.  
For example, a web server will only have access to resources with type `httpd_sys_content_t` and `httpd_sys_config_t`.  
If trying to access a file unrelated to httpd, SELinux will deny access even if the web server has DAC access.  
This is an implementation of the least privilege principle.

By default, a new file inherits the context from its parent directory.  
We can specify rules in SELinux to override this default, called a **type transition**.

```shell
chcon -t mytype_t test.txt          # temporarily change the SELinux context of a file or folder
                                    #  -u <USER>  : change the SELinux user
                                    #  -r <ROLE>  : change the SELinux role
                                    #  -t <TYPE>  : change the SELinux type
                                    #  -l <LABEL>  : change the SELinux label
                                    #  -R : apply the change recursively
                                    #  -v : verbose
                                    
restorecon -F test.txt              # restore the SELinux context of a file or folder to its default
                                    #  -F : restore also the SELinux user and role (by default only restore the type)
                                    #  -R : restore the context recursively
                                    #  -v : verbose                                                                
```

The default context mapping for each SELinux policy is stored in `/etc/selinux/<POLICY>/contexts/files`.  
It can be browsed directly, but it is better to use the `semanage fcontext` command.

```shell
semanage fcontext -l                                    # list all defined SELinux default rules
semanage fcontext -a -t mytype_t '/public(/.*)?'        # add a SELinux default rule
semanage fcontext -d -t mytype_t '/public(/.*)?'        # delete a SELinux default rule

semanage fcontext -a -e /usr/share/nginx/html/ /public  # add a default SELinux rule as a mapping to an existing rule
                                                        # all rules applied to /usr/share/nginx/html/ will apply to /public 
```

Every process on the system runs with a specific SELinux context (user + role + type).  
```shell
ps -efZ        # show the security context of running processes
```

The `targeted` policy in SELinux applies the MAC policy on processes, but not on users.  
This means that it protects against a compromised service, but not against a compromised user.  
The SELinux user of any user logged to the system is `unconfined_u` which is not restricted.  
This means that any process directly started by a user is also using `unconfined_u`.  

**SELinux booleans** can be toggled to adjust the SELinux policies to our needs.  
```shell
getsebool -a                              # display all SELinux booleans with their status
semanage boolean -l                       # more detailed info on each boolean 
setsebool httpd_read_user_content on      # switch on a SE boolean temporarily
                                          #  -P : make the change permanent
```

All SELinux policy violations are logged in `/var/log/audit/audit.log`.  
That is useful for security monitoring, but also to debug SELinux permission issues during configuration.  
```shell
sudo cat /var/log/audit/audit.log                # show all SELinux policy violations
sudo ausearch -ts recent                         # more user-friendly view of last 10min violations (including timestamp)
sudo journalctl -t setroubleshoot --sice 14:10   # more detailed info about a violation
```

SELinux also manages ports that each process can use.  
If a process tries to listen to a port outside its allowed port numbers, SELinux will not allow it.
```shell
semanage port -l                               # list all port types with the port numbers they include
semanage port -a -t http_port_t -p tcp 8888    # add port 8888/tcp to the SELinux http_port_t type
```

## Useful Linux packages

### Image Magick

Image Magick is a Linux program to manipulate and convert images.  
When installed, it provides several commands :
- `identify` to show image information
- `convert` to create a new image by editing (resize, crop, rotate...) and/or changing the format
- `composite` to overlay an image above another
- `montage` to combine multiple images into a grid

```shell
sudo apt install imagemagick

convert --version                    # ensure that ImageMagick is correctly installed

identify dog.jpg                     # show image size, format, size...
identify -verbose dog.jpg            # show a lot more information about the image, including exif info
identify -format '%wx%h' dog.jpg     # print specific information about the image in a given format

convert dog.jpg output.png                              # convert an image to a different format
convert dog.jpg -resize 100x100 output.jpg              # convert an image with a max size of 100x100
convert dog.jpg -rotate 90 output.jpg                   # rotate the image by 90 degrees
convert dog.jpg -swirl 100 -resize 100x100 output.jpg   # apply a swirl effect, then resize the image  
convert dog.jpg -crop 300x200+200+10 output.jpg         # crop a piece of an image : WIDTHxHEIGHT+OFFSET_X+OFFSET_Y

# create a montage with 2 tiles (1 image per line and 2 per column)
# each tile has size 300x200 and tiles are separated by 5 pixels spacing
montage dog1.jpg dog2.jpg -geometry 300x200+5+5 -tile 1x2 output.log
```