#!/usr/bin/env bash

sorter_func(){
    declare -Ag ext_count
    #In the "declare" above, the associative array "ext_count" is declared globally as it needs to be retrieved outside this function

    local target="$1"

    #The variable "made_dir" is used as a marker to represent if the directory for the extension being sorted exists
    local made_dir="false"

    #The variable "counter" is used to keep track of how many files meet the criteria of the extension being searched
    local counter=0
    for file in "$path"/*;do
        #The conditional below checks if the file being iterated over is a directory, if it is, then the iteration is skipped over
        [[ -d "$file" ]] && continue

        #the command "basename" takes only the file name from the files path
        #The command is required to avoid the file + its path from being compared, as just the specific file in the path is required not its path
        stripped_file=$(basename "$file")
        
        #The condition below ensures that hidden files are skipped
        [[ $stripped_file = .* ]] && continue

        
        #The file currently being checked is converted to lowercase then matched with the extension being sorted, which was previously also converted into lowercase
        lowercase_file=${stripped_file,,}
        
        #If the "directory_analysis file" is still in the directory being sorted, then it is skipped
        [[ "$lowercase_file" == "directory_analysis.txt" ]] && continue

        #the conditional below match exclusively the extension of the file being iterated over
        #for the example file, "file1.jpeg" just the extension on the file, "jpeg", will be matched with the ext, being checked
        if [[ "${lowercase_file##*.}" == $target ]];then

            #The conditional below ensures that, only if a match is found, the directory for the extension is created 
            if [[ "$made_dir" == "false" ]];then
                local dir="${target}_sorted_dir"

                mkdir -p "$path/$dir"
                made_dir="true"
            fi

            #The file is moved into its dedicated directory
            mv -n $file "$path/$dir"

            #the counter is appended by one if a match is found
            ((counter++))
        fi
    done

    #after the function iterates through all the files, the amount of files which matched the extension being sorted is kept track off in the array called "ext_count"
    ext_count["$target"]="$counter"
}

#This function is responsible for passing the extensions one by one into the  "brain" function called "sorter_func"
sort_files(){
    local extensions=("$@")
    for ext in "${extensions[@]}";do
        sorter_func "$ext"
    done
}

dir_report(){
    #if a file named "directory_analysis" exists already then it is removed and replaced with a new one
    #Users of this script are encouraged to backup or movev the file after each sorting process
    if [[ -f "$path/directory_analysis.txt" ]];then
        rm -f "directory_analysis.txt"
    fi

    touch "$path/directory_analysis.txt"

    echo "--------------------------Directory Analysis-----------------------" >> "$path/directory_analysis.txt"
    echo "----------------Done on $(date)-----------------" >> "$path/directory_analysis.txt"
    for item in "${!ext_count[@]}";do
        echo "Extension: $item, Number of files: ${ext_count[$item]}" >> "$path/directory_analysis.txt"
    done

    zenity --info --text="The file, 'directory_analysis.txt' has been made in the current directory"
}


#The function "main" is where the script starts from and ends from, all other functions are called from this functionx
main(){
    #This array holds extensions input by the user but matches were not found
    empty_ext=()
    path="$1"
    #This conditional below checks if the variable "path" has been input
    if [[ -z "$path" ]];then
        zenity --error --text='Input a valid path'
        exit
    fi
    
    #The conditional below checks if the path is actually a directory and returns an error if not
    if [[ ! -d "$path" ]];then
        zenity --error --text='The directory doesnt exist, input a valid path'
        exit
    fi

    local ext_to_be_sorted=$(zenity --entry --text='Input the extensions you want to sort by')

    #The "read" command below splits the user input into an array called extensions
    read -ra extensions <<< "$ext_to_be_sorted"
    
    #This mapfile command below will put the extensions input by the user, and filter out duplicates, into an array called "filtered _array"
    mapfile -t filtered_array < <(printf '%s\n' "${extensions[@]}" | sort -f | uniq -i)

    #In the for loop below, all extensions are converted to lowercase
    for i in "${!filtered_array[@]}";do
        filtered_array[$i]="${filtered_array[$i],,}"
    done

    #The function "sort_files" is called and the array, "filtered_array", which contains the extensions the user wants to sort is passed into it
    sort_files "${filtered_array[@]}"
    
    #Each entry into the associative array, "ext_count", is checked. If the value (number of matches to the extension) of the key, is less than one, meaning no matches for the extension were found,then the extension is moved into the array, "empty_ext"
    for ext in "${!ext_count[@]}";do
        if [[ "${ext_count[$ext]}" -lt 1 ]];then
            empty_ext+=("$ext")
        fi
    done

    #If the number of values in the array "empty_ext" is more than 0, meaning one or more extensions input by the user had no matches, then info regarding the extension(s),is given to the user
    if [[ ${#empty_ext} -gt 0 ]];then
        zenity --info --text="Matches for the following extension(s) were not found: ${empty_ext[*]}"
    fi

    #The function below creates a report into the same directory which is sorted
    dir_report
}

main $1