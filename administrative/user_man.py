import bcrypt
from database.db_schema import User
from database.db_functions import add_user, delete_user, search_user_key, change_user_key, change_user_privilege, list_admin_users, search_user_id, retrieve_user_authorization, list_users
from database.database import SessionLocal
from .logging import create_log, export_logs
import json
import getpass

confirm_options = ["y", "n"]
db = SessionLocal()
abort_opt = "You may input 'quit' to abort"

def hash_key(password: str) -> str:
    byte_prop_key = password.encode()
    salt = bcrypt.gensalt()
    key = bcrypt.hashpw(password=byte_prop_key, salt=salt)
    key = key.decode()

    return key

#This function returns a tuple, if the users account exists then regardless of their authorization, a boolean stating if they have admin privilege is returns and the second index is their username
def authenticate_authorize() -> tuple[bool, None|str]:
    username = input("Username: ")
    key = getpass.getpass("key(Input is hidden): ")

    key_in_db = search_user_key(db=db, username=username)
    if key_in_db is None:
        salt = bcrypt.gensalt()
        key_in_db = bcrypt.hashpw(password="dummy".encode(), salt=salt)
    else:
        key_in_db = key_in_db.encode()

    key = key.encode() 
    is_authenticated = bcrypt.checkpw(password=key, hashed_password=key_in_db)

    if is_authenticated is False:
        print("The credentials provided are incorrect")
        return False, None

    #NOTE:This is a boolean
    is_authorized = retrieve_user_authorization(db=db, username=username)

    assert is_authorized is not None

    if is_authorized is False:
        print("You do not have adaquate authorization")
        return False, None
    else:
        return True, username

def create_user():
    flag1 = False
    flag2 = False
    flag3 = False
    is_admin = False
    key = ""
    prop_key = ""
    while True:
        print(abort_opt)
        print("Usernames will have white space removed automatically and any uppercase will be converted to lowercase")
        prop_username = input("What is the proposed username of the user?\n").strip().lower()
        prop_username = "".join(prop_username.split())
        #The return key function is used as if None is returned by the func, then the username doesnt exist

        if prop_username.lower() == "quit":
            print("Aborting")
            break

        if len(prop_username) > 15:
            print("This username length exceeds the maximum of 15")
            continue
        
        exists=search_user_key(db=db, username=prop_username)

        if exists is not None:
            print("The proposed username already exists!")
            continue

        while True:
            prop_key =getpass.getpass("What is the proposed key of the user (Input is hidden): ")

            confirm = getpass.getpass("Input the same key again")

            if confirm != prop_key:
                print("The input keys do not match")
                continue
            else: 
                break

        flag1 = True
        key = hash_key(password=prop_key)
        break

    while flag1 is True:
        print(abort_opt)
        is_privileged = input("Does this user have administrative privileges?[y/n]: ").lower()

        if is_privileged == "quit":
            print("Aborting")
            break

        if is_privileged not in confirm_options:
            print("Select a valid option!")
            continue

        if is_privileged == "y":
            is_admin = True
        else:
            is_admin = False

        flag2 = True
        break

    while flag2 is True:
        print("The username field will always be set to lowercase")
        print(f"The users credentials are: \nUsername:{prop_username} \nKey(Hidden) \nIs admin: {is_admin}")
        confirm = input("Can you confirm the above credentials?[y/n]: ").lower()

        if confirm not in confirm_options:
            print("Select a valid option!")
            continue

        if confirm == "n":
            print("Aborting")
            break
        else:
            flag3 = True
            break

    while flag3 is True:
        new_user = User(username = prop_username,
                        user_key = key,
                        is_admin = is_admin)
        add_user(db=db, user_obj=new_user)
        print("\n \nThe new user has been added \n \n")

        #NOTE:The username of the created user is returned for logging reasons
        return True, prop_username

    return False, ""

def remove_user():
    flag1 = False
    while True:
        print(abort_opt)
        target_user = input("What is the username of the account to be deleted?\n")

        if target_user.lower() == "quit":
            print("Aborting")
            return False, ""

        exists = search_user_key(db=db, username=target_user)

        if exists is None:
            print("The user doesnt exist")
            continue
        else:
            flag1 = True
            break

    while flag1 is True:
        confirm = input(f"Can you confirm that the account: {target_user}, is to be deleted? [y/n]: ").lower()

        if confirm not in confirm_options:
            print("Select a valid option!")
            continue

        if confirm == "n":
            print("Aborting")
            return False, ""
        else:
            delete_user(db=db, target_username=target_user)
            print("\n \nThe user has been deleted \n \n")
            #NOTE: The username of the deleted account is returned for logging purposes
            return True, target_user

    return False, ""

def change_key():
    flag1 = False
    while True:
        print(abort_opt)
        target_username = input("What is the name of the account to have its key changed?:\n")

        if target_username.lower() == "quit":
            print("Aborting")
            return False, ""

        current_key = search_user_key(db=db, username=target_username)

        if current_key is None:
            print("The user does not exist")
            continue
        else:
            flag1 = True
            break

    while flag1 is True:
        while True:
            prop_key = getpass.getpass("What is the proposed new key of the user: ")
        
            confirm = getpass.getpass("Input the same key again")
        
            if confirm != prop_key:
                print("The keys do not match")
                continue
            elif prop_key == current_key:
                print("The new key can not be the same as the old one")
                continue
            else: 
                break

        hashed_key = hash_key(password=prop_key)
        change_user_key(db=db, target_username=target_username, new_key=hashed_key)
        print("\n \n The users key has been changed \n \n ")
        return True, target_username
    
    return False, ""

def list_administrators():
    administrators=list_admin_users(db=db)
    admin_counter = 0
    print("\n\nThe list of administrators is as follows:")
    print(f"User ID | Username ")
    for admin in administrators:
        admin_counter += 1
        print(f"{admin.user_id}  |  {admin.username}")

    print(f"\nThe number of administrators is: {admin_counter} \n \n")

def list_all_users():
    users = list_users(db=db)
    user_counter = 0
    print("\n\nThe list of users is as follows:")
    print(f"User ID | Username ")
    for user in users:
        user_counter += 1
        print(f"{user.user_id}  |  {user.username}")

    print(f"\n\nThe number of users is: {user_counter} \n \n")

#This function changes the privilages of an account
def change_priv(logged_in_user:str):
    flag1 = False
    is_up_priv = False
    while True:
        print(abort_opt)
        target_username = input("What is the username of the account to have its privileges changed?\n")

        #NOTE: This is a security feature to prevent no one from having admin privileges
        if target_username == logged_in_user:
            print("You can't change your own privileges")
            break

        if target_username.lower() == "quit":
            print("Aborting")
            return False, ""

        exists = search_user_key(db=db, username=target_username)

        if exists is None:
            print("The user does not exist")
            continue
        else:
            flag1 = True
            is_admin = retrieve_user_authorization(db=db, username=target_username)

            assert is_admin is not None
            print(f"is admin is: {is_admin}")
            print("This user is an administrator " if is_admin is True else "This user is not an administrator")
            break

    while flag1 is True:
        print(abort_opt)
        new_privilege = input("Should the user have administrative privileges [y/n]: ").lower()

        if new_privilege== "quit":
            print("Aborting")
            return False, ""

        if new_privilege not in confirm_options:
            print("select a valid option")
            continue
        elif new_privilege == "n":
            is_up_priv = False
            change_user_privilege(db=db, target_username=target_username, admn_privilege=False)
        else:
            is_up_priv = True
            change_user_privilege(db=db, target_username=target_username, admn_privilege=True)

        print("\n \nThe users administrative privileges have been changed \n \n")
        return True, target_username, is_up_priv
    
    return False, ""

def main():
    flag1 = False
    attempts = 0
    logged_in_username = ""
    while True:
        if attempts == 3:
            print("You have exceeded the maximum allowed number of attempts")
            break

        is_allowed = authenticate_authorize()

        if is_allowed[0] is False:
            attempts += 1
        else:
            logged_in_username = is_allowed[1]
            flag1 = True
            break

    assert logged_in_username is not None
    
    logged_in_user_id = search_user_id(db=db, target_username=logged_in_username)
    assert logged_in_user_id is not None

    while flag1 is True:
        try:
            print("1. Add a user. \n2. Remove a user. \n3. Change a users key. \n4. Change a Users privileges. \n5. Show all current administrators. \n6. Retrieve all logs. \n7. Retrieve a users logs \n8. List all users \nInput '0' to exit.")
            choice = int(input("What would you like to do?: "))
        except ValueError:
            print("Select a valid number")
            continue

        match choice:
            case 1: 
                confirmation = create_user()
                if confirmation[0] is True:
                    create_log(log_type="administrative", log_detail="new_user", admin_data=confirmation[1], subject_name=logged_in_username, subject_id=logged_in_user_id, db=db)
            case 2: 
                confirmation = remove_user()
                if confirmation[0] is True:
                    create_log(log_type="administrative", log_detail="deleted_user", admin_data=confirmation[1],subject_name=logged_in_username, subject_id=logged_in_user_id, db=db)

            case 3: 
                confirmation = change_key()
                if confirmation[0] is True:
                    create_log(log_type="administrative", log_detail="password_change", admin_data=confirmation[1],subject_name=logged_in_username, subject_id=logged_in_user_id, db=db)

            case 4: 
                confirmation = change_priv(logged_in_user=logged_in_username)
                if confirmation[0] is True:
                    if confirmation[2] is True:
                        create_log(log_type="administrative", log_detail="up_priv", admin_data=confirmation[1],subject_name=logged_in_username, subject_id=logged_in_user_id, db=db)
                    else:
                        create_log(log_type="administrative", log_detail="down_priv", admin_data=confirmation[1],subject_name=logged_in_username, subject_id=logged_in_user_id, db=db)

            case 5:
                list_administrators()

            case 6:
                logs = export_logs(retrieve_all=True,db=db)
                with open("logs.json", "w") as file:
                    json.dump(obj=logs, fp=file, indent=4)

                print("\n \nAll logs have been exported \n \n")

            case 7:
                while True:
                    print(abort_opt)
                    target_username = input("What is the username of the user whose logs you want to retrieve: ")

                    if target_username.lower() == "quit":
                        break

                    target_userid = search_user_id(db=db, target_username=target_username)
                    
                    if target_userid is None:
                        print("This user doesnt exist")
                        continue
                    else: 
                        logs = export_logs(db=db, target_userid=target_userid, retrieve_all=False)
                        with open("individual_logs.json", "w") as file:
                            json.dump(obj=logs, fp=file, indent=4)        
                            print("\n \n All logs have been exported\n \n ")

            case 8:
                list_all_users()

            case 0: 
                print("Exiting")
                break
            case _: 
                print("Select a valid choice")
                continue

if __name__ == "__main__":
    main()
