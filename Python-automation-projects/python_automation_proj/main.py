import requests
import hashlib
from pathlib import Path
import json
from time import sleep
from datetime import datetime

#This is a custom error type created to facilitate the process of catching errors
class InvalidPath(Exception):
    pass

'''This class will handle creation, validation, and retrieval of the application's configuration'''
class ConfigController():
    def __init__(self):
        pass
    
    '''Restores a single configuration entry to its default value without overwriting the remainder of the configuration file'''
    def reset_path(self, path_type: str):
        with open("config.json", "r") as f:
            config=json.load(fp=f)

        if path_type == "results_path":
            config[path_type] = None

        if path_type == "acc_list_path":
            config[path_type] = str(Path("./acc_list.json"))

        with open("config.json", "w") as file:
            json.dump(obj=config, fp=file, indent=4)

        return Path(config[path_type])


    '''This method will search for the results path and return it or if it is set to None it will return None'''
    def find_results_path(self):
        with open("config.json", "r") as f:
            config=json.load(fp=f)

        if "results_path" not in config:
            print("The key to the path to the the directory where the results will be stored doesnt exist \nUsing default")
            config["results_path"] = None

            with open("config.json", "w") as f:
                json.dump(obj=config, fp=f, indent=4)

            return None
        
        path = config["results_path"]

        if path is not None:

            if not Path(path).exists():

                print("The key for the 'results_path' doesnt exist or its value is an invalid path \nUsing the default instead")
                path = self.reset_path(path_type="results_path")  
                
        return path
    
    ''' Retrieves the configured account list path and verifies that it points
        to an existing file. If validation fails, the default path is restored.'''
    def find_acc_list_path(self):
        script_path = Path(__file__).parent
        
        try:    
            with open("config.json", "r") as f:
                config=json.load(fp=f)

            if "acc_list_path" not in config:
                raise InvalidPath

            acc_list_path = config["acc_list_path"]

            path = script_path / acc_list_path   

            if not Path(path).exists():
                raise InvalidPath

        except InvalidPath:
            print("The key for the 'account_list_path' doesnt exist or its value is an invalid path \nA new path has been created, verify the new value")
            path = self.reset_path(path_type="acc_list_path")
        except json.decoder.JSONDecodeError:
            print("An error has occured with the json file \nVerify default created" )
            self.create_default_config()
            return None
        
        return path
    
    def create_default_config(self) -> None:
        config_dict={
            "acc_list_path": str(Path("./acc_list.json")),
            "results_path": None
        }

        path = Path(__file__).parent / "config.json"

        #If the configuration file exists but is corrupted then this conditional will delete it and teh following statemnet will create a new one
        if path.exists() is True:
            path.unlink()
        
        path.touch()

        with open("config.json", "w") as f:
            json.dump(obj=config_dict, fp=f, indent=4)

        print("The default configuration file has been created")

    '''The Entry point for configuration validation, it ensures the configuration file exists, is valid JSON and that all required paths are usable.'''
    def configuration(self) -> tuple[bool, Path | None, Path | None]:
        if Path("./config.json").exists() is True:
            try:
                #The point of this is to catch errors stemming from opening the file are present
                with open("config.json", "r") as file:
                    json.load(fp=file)

            except OSError|json.JSONDecodeError:
                    return (False, None, None)

        else:
            while True:
                user_choice = input("The configuration file doesnt exist in its intended location \n Load default [y/n]?")
                match user_choice.lower():
                    case "y":
                        self.create_default_config()
                        print("Default configuration file loaded")
                        break
                    case "n":
                        print(f"If you have a configuration file saved somewhere else move it to the same directory as this script which is {Path(__file__).parent}")
                        return (False, None, None)
                    case _:
                        print("Select a valid option!")
                        continue

        acc_list_path = self.find_acc_list_path()
        if acc_list_path is None:
            return (False, None, None)
        
        results_storage_path = self.find_results_path()

        return (True, acc_list_path, results_storage_path)

'''This class will Perform password breach lookups using the Have I Been Pwned k-Anonymity API'''
class Searcher():
    def __init__(self, acc_list_path: Path | None, result_path: Path | None):
        self.acc_list_path = acc_list_path 
        self.result_path = result_path

    def singular_scan(self, target: str):

        byte_password = target.encode()
        sha1_password = hashlib.sha1(string=byte_password).hexdigest().upper()
        
        #The line below will take the first 5 characters of the hash
        prefix = sha1_password[0:5]
        suffix = sha1_password[5:]

        url = f"https://api.pwnedpasswords.com/range/{prefix}"

        for _ in range(4):   
            try:
                response = requests.get(url=url, timeout=8)
                response.raise_for_status()
                break
            except requests.exceptions.RequestException as error:
                last_err = error
                sleep(8)
                continue
        else:
            print(f"The error: {last_err} has occured")#type: ignore

        for line in response.text.splitlines(): #type: ignore
                ret_suffix, count = line.split(":")
                if ret_suffix == suffix:
                    print(f"The target has appeared the following times: {count}")
                    return 1

        print("The target has Not appeared")

    '''This method coordinates the batch scanning process'''
    def search_file(self) -> bool:
        is_first_entry = True
        try:
            with open(self.acc_list_path, "r") as file: #type: ignore
                acc_list = json.load(fp=file)
        except json.JSONDecodeError:
            print("The file holding the accounts may be corrupted")
            return False
        except FileNotFoundError:
            print("Verify if the account list file exists")
            return False
        
        #This checks if the acc_list json file is empty and returns false if it is
        if not acc_list:
            print("There are no accounts in the account list")
            return False

        for ref, password in acc_list.items():
            result = self.make_request(password=password)

            if result[0] is True:
                    self.record_result(ref=ref, count=result[1], is_error=False, error=result[1], is_first=is_first_entry)
                    is_first_entry = False
            else:
                    self.record_result(ref=ref, count=result[1], is_error=True, error=result[1], is_first=is_first_entry)
                    is_first_entry = False

        return True
            
    def record_result(self, ref: str, count: int, is_error: bool, error, is_first: bool) -> None:
        if self.result_path is None:
            path = Path.cwd() / 'results.txt'
        else:
            script_path = Path(__file__).parent
            path = script_path / self.result_path

        if path.exists() is True:
            with open(path, "a") as file:
                if is_first is True:
                    time = datetime.now()
                    file.write(f"Done on: {time}\n")

                if is_error is True:
                        file.write(f"{ref}:ERROR, {error}\n")
                else:
                        file.write(f"{ref}:{count}\n")

        else:
            with open(path, "w") as file:
                if is_first is True:
                    time = datetime.now()
                    file.write("\n\n")
                    file.write(f"Done on: {time}\n")

                if is_error is True:
                    file.write(f"{ref}:ERROR, {error}\n")

                else:
                    file.write(f"{ref}:{count}\n")


    #This method is responsibe for extracting responses and making the query to HIBP API server
    def make_request(self, password: str) -> tuple:
        byte_password = password.encode()
        sha1_password = hashlib.sha1(string=byte_password).hexdigest().upper()
        
        '''The HIBP k-Anonymity API uses only the first five SHA-1 characters in the hash to help preserve password privacy'''
        prefix = sha1_password[0:5]
        # The API returns only hash suffixes matching the supplied prefix.
        suffix = sha1_password[5:]

        url = f"https://api.pwnedpasswords.com/range/{prefix}"

        ok_flag = False
        for _ in range(4):    
            try:
                response = requests.get(url=url, timeout=5)
                response.raise_for_status()
            except requests.exceptions.Timeout:
                last_err = "Timeout"
                sleep(8)
                continue
            except requests.exceptions.RequestException as error:
                last_err = error
                sleep(8)
                continue
            else:
                ok_flag = True
                break

        if ok_flag == False:
            return (False, last_err) # type: ignore This type of unbound error will never actually occur due to the condtionals in place

        for line in response.text.splitlines(): # type: ignore
                ret_suffix, counter = line.split(":")
                if ret_suffix == suffix:
                    return (True, int(counter))
        
        #IF no match is found then the returned counter is set to 0
        return (True, 0)


#This function coordinates the batch scanning process
def main_scan():
    processor = ConfigController()
    confirmation = processor.configuration()

    if confirmation[0] is False: # type: ignore
        print("The file holding the configuration details is in the incorrect format")
        return 

    acc_list_path = confirmation[1] # type: ignore
    results_path = confirmation[2] #type: ignore    

    if results_path is None:
        print("The json file path of the accounts being checked was ", acc_list_path, "\nThe path to the results is the current working directory" )
        searcher = Searcher(acc_list_path=acc_list_path, result_path = None) # type: ignore
    else:
        print("The json file path of the accounts being checked was ", acc_list_path, "\nThe path to the results is ", results_path )
        searcher = Searcher(acc_list_path=acc_list_path, result_path=results_path) # type: ignore

    result = searcher.search_file()

    if result is False:
        return
    else:
        print("DONE")
        return 

#This function is responsible for starting the singular scan option
def secondary_scan():
    searcher = Searcher(None, None)

    target = input("What is the target: ")

    print(f"The results for {target} are:")

    searcher.singular_scan(target=target)

def main():
    while True:
        scan_type = str(input("What is the type of scan that you would like to do, file: input 1, singular: input 2\n"))
        
        if scan_type not in ['1', '2']:
            print("select a valid option")
            continue
        else:
            break

    if scan_type == '1':
        main_scan()
    else:
        secondary_scan()


if __name__ == "__main__":
    main()
