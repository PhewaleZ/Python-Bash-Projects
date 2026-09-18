# SORTER.SH documentation

## OVERVIEW

This is the documentation for my personal project called `sorter`. The aim of this project was to explore more advanced bash concepts as well as polish up on my current understanding of bash scripting fundementals. The code I have written serves one purpose, which is to sort files in a directry based on the extensions input by the user, meaning if a user wants to sort `.txt` files (or even files ending with anything after a dot such as `.random`), my bash script will place all files which match the extension into a serperate appropriately named directory. My code does take edge cases into account to ensure smooth usage.

My script will standardize all uppercase inputs into lowercase as well  only select unique inputs made by the user, meaning that if two
It should be noted that my script will ignore hidden files, meaning files with the following format `.filename`. This was a deliberate choice on my end as files may be hidden for a reason and therefore should not be touched.

This script makes usage of the bash command called `zenity`, to provide an easy to use GUI interface which i believe will provide easier use to those less familiar with linux systems such as the terminal.

For more information on the code in the script, I suggest you open it and review it as i have provided adaquate comments throughout the script

## WHAT I LEARNED

Throughout the week i have spent on this project, I have learned the following:

+ How to pass arrays and associative arrays into a function
+ How to better structure a script by splitting it into multiple functions which have a specific role for the purpose of better readability
+ How to incorporate `zenity` into my scripts
+ How to better manipulate and filter strings through commands like `basename` and `mapfile`
+ How to convert a string into an array with the `read` command
+ How to make use of the following format, to save time on skipping iterations in a loop

```bash
[[  conditional_here ]] && continue
```

+ How to pass terminal input into a bash script
+ How to use the command `printf`
+ How to create, append to and properly format an analysis file
+ Various bash quirks such as:

```bash
"${string,,}" # To convert a string to lowercase
"${string^^}" #To convert a string to uppercase
"${#array}" #to return the number of values in an array
```

## HOW TO USE

### REQUIREMENTS

+ The command zenity installed on your device, which can be using the appropritate installation (based on your linux distro) command on your termial, for example:

Debian based
`sudo apt install zenity`

Fedora based
`sudo dnf install zenity`

CentOS/RHEL
`sudo yum install zenity`

To verify if it has been installed, input the command into your terminal: `zenity --version`

+ A 4.0+ version of bash, if this isnt the case i advise that you update your version of bash

### EXAMPLE

In this Github repo, I have included a directory called `test1`. Within this directory, some empty files with the following extensions varying in uppercase and lowercase: py, txt, json, log and 2 hidden files and a random directory called `random_dir1`

#### STEPS

1. Run the script by inputing the following, in the directory which the script is located in, `bash sorter.sh [target directory here]`. In this case we are targeting the directory called `test1` so input the following `bash sorter.sh test1`.
2. Then simply follow the prompt requests made by the easy to interact with GUI, to input the extensions you want to sort, in this case we will input the following: "py" "json" "txt" "log" "c", leave an empty space between each extension and do not input quotation marks.
3. The script will sort out the the files in the directory and will inform you that no matches were found for the extension "c". This sort of info will only appear if a match wasnt found for one or more extensions.
4. You will be informed of a ".txt" file being created, called `directory_analysis.txt`. This file contains te number of files matched to each extension along with the date and time the sorting process took place.
5. You can view the contents of this file by inputting the following command `cat directory_analysis.txt` or by opening it. Take note that this "analysis file" is always created in the directory which was sorted.
