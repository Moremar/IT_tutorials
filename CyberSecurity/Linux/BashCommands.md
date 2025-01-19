# Bash commands


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
  - `-s` : print the allocated size of each file (in blocks)
  - `-S` : sort by file size
  - `-h` : display the size in human-readable format (K/M/G)
  - `-R` : recursive list (display files grouped by sub-folder)
  - `--color={auto|always|never}` : use colors for the output


- `tree <DIR>` : display a directory as a tree structure


- `touch <FILE>` : create an empty file, or update the modification time if the file exists


- `basename <FILE>` : show the base name of the file (without the full path) 


- `dirname <FILE>` : show the directory of the file 


- `file <FILE>` : give details about a file (file type and size on disk)


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


- `find <DIR>` : list files and folders matching filter conditions
  - `-type {f|d}` : list only files/directories
  - `-mtime -7` : filter on files/directories modified in the last 7 days
  - `-size +10M` : filter on files/directories bigger than 10M
  -  `-name result*` : filter on a regex on the file or directory name
  - `-delete` : delete the matching files/directories


- `cat <FILE>` : display the content of a file in the console


- `head <FILE>` / `tail <FILE>` : display the first/last 10 lines of a file or stdin in the console
  - `-n 5` : specify the number of lines to display
  - `-c 5` : specify the number of bytes to read instead


- `less <FILE>` : print a page of a text file (replace the older `more` command)
  - `b` : move backwards to the previous page
  - `f` : move forwards to the next page
  - `50p` : navigate to 50% of the text
  - `=` : display info about the current position
  - `-N` : show line numbers
  - `/hello` : look forwards for a string in the file
  - `?hello` : look backwards for a string in the file
  - `q` : quit the file


- `wc <FILE>` : count the number of lines, words and bytes
  - `-l` : only show the number of lines
  - `-w` : only show the number of words
  - `-c` : only show the number of bytes


- `du <FILE OR FOLDER>` : display disk usage for a file or each file in a directory
  - `-s` : only show a summary for a directory (instead of one line per file)
  - `-h` : human-readable units using K/M/G (by default it uses blocks)
  - `-m` : set the unit to Mb


- `nano <FILE>` : basic command-line text editor, user-friendly alternative to `vim`


- `sort <FILE>` : sort the content in a file (or from stdin)
  - `-r` : reverse the order
  - `-n` : sort according to numerical order
  - `-k 5` : sort according to the 5th column
  - `-u` : unique values (no duplicates)
  - `-R` : sort in a random order (useful for quizz options for example)


- `uniq` : remove adjacent duplicate lines on a sorted input
  - `-d` : only keep duplicates
  - `-u` : only keep unique lines


- `grep <PATTERN> <FILE>` : look for a pattern in a file or in stdin
  - `-F` : interpret the pattern as a fixed string instead of the default Basic Regular Expression (BRE)
  - `-E` : enable Extended Regular Expression (ERE) instead of the default BRE 
  - `-P` : enable Pearl-Compatible Regular Expression (PCRE) instead of the default BRE
  - `-i` : case-insensitive matching
  - `-n` : show the line number of the match
  - `-o` : only show the matching part, not the full line
  - `-r` : recursive search in sub-directories
  - `-c` : count the number of lines in which the pattern is found (each line counts only once)
  - `-s` : suppress errors about non-existent files or missing permissions 
  - `-l` : only show the name of the files that have a match
  - `-v` : invert match, matches lines that do not contain the pattern
  - `-q` : check if a pattern is present, exit with code 0 if present, else 1
  - `--color` : highlight the match in color  
  Basic Regular Expression allows the use of the following meta-characters :
  - `.` : any single character except newline
  - `^` : beginning of the line
  - `$` : end of the line
  - `\ ` : escape characters that have a special meaning in the regular expression, like `\.`, `\^`, `\$`...
  - `*` : quantifier for 0 or more occurrences of the previous letter or block
  - `[aeiou]` : character class, that matches any character in the square brackets
  - `[a-zA-Z]` : range class, that matches any character in the range
  - `[^abc]` : negating class, that matches any character that is not included in the character or range class
  - `[[:digit:]]` : named character class, also : `lower`, `upper`, `alpha`, `alnum`, `blank` (space and tab)
  - `\([a-z][0-9]\)` : character group using backslash-brackets, used to set a quantifier to a group    
  ERE extends BRE, it is mostly compatible with BRE and adds new matching syntax and quantifiers :
  - `([a-z][0-9])` : simpler syntax for character group (only incompatibility with BRE)
  - `(aaa|bbb)` : alternation, matches one of the 2 alternatives
  - `?` : quantifier for 0 or 1 occurrence of the previous letter or block
  - `+` : quantifier for 1 or more occurrences of the previous letter or block
  - `{3}` : quantifier to match a block repeated exactly 3 times
  - `{3,5}` : quantifier to match a block repeated 3 to 5 times
  - `\<` and `\>` : indicate the beginning or the end of a word (`\<f` matches words starting with 'f')   
  PCRE extends ERE and is not available on all implementations of `grep`, but is usually included in the GNU implementation.  
  PCRE is the regex engine used by most programming languages.
  - `\d` : matches any digit, equivalent of `[0-9]` or `[[:digit:]]`
  - `\D` : matches any non-digit character
  - `\s` : matches any whitespace character (space, tab, newline...)
  - `\S` : matches any non-whitespace character
  - `\w` : matches any word character (lower/upper-case letter, digit or underscore)
  - `\W` : matches any non-word character
  - `\d+(?= days)` : look-ahead, matches any number that is followed by " days"
  - `\d+(?! days)` : negative look-ahead, matches any number that is not followed by " days"
  - `(?<=still )\d+` : look-behind, matches any number that follows "still "
  - `(?<!still )\d+` : negative look-behind, matches any number that does not follow "still "


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


- `date +<FORMAT>` : display the current date in a specific format
  - `%H` : hour (24h)
  - `%I` : hour (12h)
  - `%p` : AM or PM
  - `%M` : minute
  - `%S` : second
  - `%T` : 24h format time, equivalent to `%H:%M:%S`
  - `%m` : month
  - `%d` : day
  - `%Y` : year


- `gzip <FILE>` : compress a file by gzip compression (GNU zip) with extension `.gz`
  - `-k` : also keep the original file (by default it removes it)
  - `-v` : verbose mode
  - `-d` : decompress a gzip compressed file (can also use the `gunzip` command instead)


- `bzip2 <FILE>` : compress a file by bzip2 compression with extension `.bz2`, slower and more efficient than gzip
  - `-k` : also keep the original file (by default it removes it)
  - `-v` : verbose mode
  - `-d` : decompress a bzip2 compressed file (can also use the `bunzip2` command instead)


- `xz <FILE>` : compress a file by LZMA compression with extension `.xz`, most advanced compression
  - `-k` : also keep the original file (by default it removes it)
  - `-v` : verbose mode
  - `-d` : decompress a xz compressed file (can also use the `unxz` command instead)
  - `-e` : extreme compression, take more CPU to compress even more efficiently


- `tar czvf <OUTPUT_FILE> <FOLDER>` : create or extract a compressed tar archive.
  - `-c` : create a new archive
  - `-x` : extract an archive
  - `-z` : compress/decompress an archive with gzip
  - `-j` : compress/decompress an archive with bzip2
  - `-J` : compress/decompress an archive with xz
  - `-v` : verbose mode
  - `-f <OUTPUT_FILE>` : specify the name of the archive to create/extract
  - `-C <FOLDER>` : specify the name of the folder to extract the archive into
  - `-t` : list the content of an archive
```shell
tar -cvf data.tar ./data           # create an archive
tar -czvf data.tgz ./data          # create a compressed archive (gzip)
tar -tf data.tgz                   # list the content of an archive
tar -xzvf data.tgz                 # decompress an archive
```


- `history` : show the history of commands executed in this terminal  
  Bash history is persistent and stored in the `~/.bash_history` file.  
  We can control the history file and history size with variables `HISTFILE` and `HISTSIZE`.   
  - `-c` : clear the command history
  - `-d 150` : delete command history entry at position 150
```shell
!!               # execute the most recent command in the history
!150             # execute the command in the history at position 150
!-3              # execute the 3rd most recent command in the history
!cd              # execute the most recent command that starts with "cd"
!?cd?            # execute the most recent command that contains "cd"
```

- `flock mylock.txt <CMD>` : take an exclusive lock (create the lock file if needed) and run a command once the lock is obtained
  - `-n` : if the lock is already taken, exit immediately instead of waiting for the lock
  - `-E 0` : return status when exiting due to the `-n` flag (0 for OK status)


- `which <CMD>` : show the full path of a shell command
  - `-a` : print all matching executables (not only the first)


- `ping <IP>` : send ICMP packets to an IP to test the connection
  - `-c 4` : send 4 ICMP packages (by default send infinitely)
  - `-i 3` : wait 3 seconds between each packet (default to 1 second)


- `man <CMD>` : display the manual of a command


- `sudo <CMD>` : run a command as superuser, require user password and the user must be allowed to use sudo
```shell
sudo ls                       # run ls with root permission
sudo -l                       # show what the current user can do in sudo
sudo -l -U <USERNAME>         # show what a specific user can do in sudo
sudo su                       # switch to the root user
su <USERNAME>                 # switch to a specific user (require password)
su -l <USERNAME>              # start a login shell with the specified user (inheriting more env variables)
sudo deluser <USERNAME> sudo  # delete a user from the sudo group
```


- `watch <CMD>` : run a command periodically in the terminal
  - `-n 3` : run the command every 3 seconds


- `time <CMD>` : measure the time that a command takes to run


- `echo '1.5 + 2.3' | bc` : basic calculator, evaluate a math string and return the result of the operation


- `source <SCRIPT>` : execute a script in the current context (so variables defined in the script persist)


- `awk '<PATTERN> { <ACTION> }' <FILE>` : text-processing tool and programming language, used mostly with CSV files and tabular data.  
  It has a rich language, but is being replaced by Python for complex text analysis.  
  It processes a file line by line, and executes the action if the line matches the pattern.  
  It breaks the lines into column (with space delimiter by default) and makes each column available with parameters $1, $2 ...
```shell
awk '/aaa/' file                             # print all lines containing "aaa" (action omitted so by default print the entire line)
awk '$2 > 10' file                           # print all lines where the 2nd column is a number bigger than 10
awk '{ print $2 }' file                      # print the 2nd column for each line (pattern omitted so by default every line matches)
awk -F ',' '{ print $2 }' file               # print the 2nd column for each line for a comma-separated file
awk '{ sum += $1 } END { print sum }' file   # sum the first column of each line of a file and print this sum
```


- `wget http://example.com/file.zip` : non-interactively download a file from a URL and save it in the current directory.  
  wget can download an entire website and pause/resume downloads (which curl cannot), but it cannot upload data. 
  - `-O <FILE_NAME>` : specify the name of the file saved locally
  - `-c` : resume an interrupted download from where it stopped
  - `-b` : run the download in the background and output in a log file instead of the standard output of the terminal
  - `-q` : quiet mode, do not generate any output
  - `-i <TXT_FILE>` : provide an input .txt file with the list of files to download
  - `-r` : recursive download, to download links in the target website or sub-folders of the target folder
  - `-p` : download all website pre-requisites like stylesheets, scripts, images... (used when downloading a website)
  - `-k` : converts links in the downloaded website to reference the local files
  - `-l 5` : set the maximum recusion level to 5
  - `-A jpg` : limit the links followed in the recursion to accept only specific extensions (jpg only here)


- `curl <OPTIONS> <URL>` : fetch and display web pages or API content, supporting multiple protocols (HTTP, HTTPS, FTP, SFTP...)  
  It takes a URL-encoded string as URL, and displays the response in stdout.   
  It must be installed with `sudo apt install curl`  
  `curl 'https://www.example.com/api.php' -G --data-urlencode 'param1=New York' --data-urlencode 'param2=aaa'`
  - `-v` : verbose
  - `-o <FILE>` : save output to a file
  - `-s` : silent mode (do not show errors or progress bar)
  - `-G` : force an HTTP GET request (default to POST if `--data` or `--data-urlencode` is provided)
  - `-d <DATA>` : send the data to a POST request
  - `--data-urlencode <DATA>` : same as `-d` but perform URL-encoding on the data (to replace every space by `%20` for example)
  - `--fail` : on HTTP failure, curl exits with failure code 22 instead of creating the output returned by the server


- `md5sum <FILE>` : calculate the MD5 hash of a file
```shell
md5sum test.txt                 # hash of a file
echo -n "iloveu" | md5sum       # hash of a string
```


- `shasum -a 1 <FILE>` : calculate the SHA-1 hash of a file, we can also use variations of SHA-2.  
  SHA algo-specific commands also exist : `sha224sum`, `sha256sum`, `sha512sum` ...
```shell
shasum file.txt                             # calculate the SHA-1 hash of the file
shasum -a 1 file.txt                        # same (explicitly specify SHA-1 instead of defaulting it)
sha1sum file.txt                            # same, using the SHA-1 specific command
sha256sum file.txt                          # calculate the SHA-256 hash of the file
echo "<MD5_HASH> <FILE>" | shasum --check   # check if the hash in the input is valid
```


- `jq` : command-line JSON parser to parse and retrieve fields in JSON files.  
  It must be installed with `sudo apt install jq`
```shell
cat file.json | jq                                # pretty-print the JSON file
                                                  #  -r : raw string (does not include color code)
                                                  #  -c : compact (on a single line instead of pretty-print) 
cat file.json | jq '.name'                        # print the value of the "name" property
cat file.json | jq '[.name, .age]'                # print an array with the values of the name and age properties
cat file.json | jq '.hobbies[0].name'             # print the name of the first hobby inside the hobbies array property
cat file.json | jq '.hobbies[].name'              # print the name of each hobby inside the hobbies array property
cat file.json | jq '.hobbies[]' | jq '.[].name'   # same, but using multiple linked calls to jq
cat file.json | jq '.hobbies | length'            # print the length of the hobbies array using the length operator
```


- `strings myBinary` : display all the printable strings from a binary file.  


- `ltrace ./myBinary` : debugging tool that displays the shared library calls made by the binary and their results.  
  It is a useful tool to understand what a binary is doing.


- `lsof` : list open files on the system
  - `-p 1234` : restrict to a specific process ID
  - `-c <PROCESS_NAME>` : restrict to a specific process name
  - `-u <USER_NAME>` : restrict to a specific user
  - `-i` : restrict to open network connections
  - `-i :53` : restrict to open network connections on a specific port


- `base64 file.txt` : encode a file in base64
  - `-d` : decode the file instead


- `hostname` : display the hostname of the machine, to reach it from the local network (with the `.local` suffix) 


- `stat <FILE>` : give detailed info on a file : file type, permissions, inode number, hard link count, creation date...


- `lsb_release -a` : display Linux Standard Base (LSB) info : name, version, code name...


- `screen` : open a virtual terminal in the background, and connect the local terminal to it.  
             It looks like a normal terminal, but it has created a session that other users can interact with.  
             It is very useful to create a shared terminal for debugging remotely with a colleague.
  - `screen -list` : list all existing screen sessions
  - `screen -x <SESSION_NAME>` : join an existing session, so we can enter commands and see anything happening on the terminal
  - `Ctrl-A Ctrl-D` : detach from the session (keep the session alive in the background)
  - `exit` : terminate the session and detach all terminals that joined it
