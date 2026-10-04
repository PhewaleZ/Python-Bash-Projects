from database.db_functions import add_user, delete_user, return_key
from database.database import SessionLocal
import bcrypt
from database.db_schema import User
options = ["y", "n"]
db = SessionLocal()
abort_opt = "You may input 'quit' to abort"
def authenticate():
    username = input("Username: ")
    password = input("Password: ")

    result = return_key(db=db, username=username)
    if result is None:
        password_in_db = "dummy".encode()
    else:
        password_in_db = result["user_key"].encode()

    password = password.encode()
    is_auth=bcrypt.checkpw(password=password, hashed_password=password_in_db)

    return True if is_auth is True else False

def create_user():
    flag1 = False
    flag2 = False
    flag3 = False
    is_admin = False
    db = SessionLocal()
    key = ""
    prop_key = ""
    while True:
        print(abort_opt)
        prop_username = input("What is the proposed username of the user?\n")
        #The return key function is used as if None is returned by the func, then the username doesnt exist

        if prop_username.lower() == "quit":
            print("Aborting")
            break

        exists=return_key(db=db, username=prop_username)

        if exists is not None:
            print("The proposed username already exists!")
            continue

        prop_key = input("What is the proposed key of the user?\n")

        confirm = input(f"Can you confirm {prop_key}? [y/n]:\n").lower()

        if confirm not in options:
            print("select a valid option")
            continue

        if confirm =='n':
            continue
        else:
            flag1 = True
            byte_prop_key = prop_key.encode()
            salt = bcrypt.gensalt()
            key = bcrypt.hashpw(password=byte_prop_key, salt=salt)
            key = key.decode()
            break

    while flag1 is True:
        print(abort_opt)
        is_priv = input("does this user have administrative privileges?: [y/n]").lower()

        if is_priv == "quit":
            break

        if is_priv not in options:
            print("Select a valid option!")
            continue

        if is_priv == "y":
            is_admin = True
        else:
            is_admin = False

        flag2 = True

        break

    while flag2 is True:
        print(f"The users credentials are: \nUsername:{prop_username} \nKey:{prop_key} \nis admin: {is_admin}")
        fin_confirm = input("can you confirm the above credentials?[y/n]:\n").lower()

        if fin_confirm not in options:
            print("Select a valid option!")
            continue

        if fin_confirm == "n":
            print("Aborting")
            break
        else:
            flag3 = True
            break
        #The final step is to write to the database

    while flag3 is True:
        new_user = User(username = prop_username,
                        user_key = key,
                        is_admin = is_admin)
        add_user(db=db, user_obj=new_user)
        print("The new user has been added")
        break

def remove_user():
    flag1 = False
    while True:
        print(abort_opt)
        target_user = input("What is the username of the account to be deleted?\n")

        if target_user.lower() == "quit":
            print("Aborting")
            break

        exists = return_key(db=db, username=target_user)

        if exists is None:
            print("The user doesnt exist")
            continue
        else:
            flag1 = True
            break

    while flag1 is True:
        confirm = input(f"Can you confirm that the account: {target_user}, is to be deleted?: [y/n]\n").lower()

        if confirm not in options:
            print("Select a valid option!")
            continue

        if confirm == "n":
            print("Aborting")
            break
        else:
            delete_user(db=db, target_username=target_user)
            print("The user has been deleted")

        break

def change_password():
    while True:
        flag1 = False
        print(abort_opt)
        target_user = input("What is the name of the account to have its password changed?:\n")

        if target_user.lower() == "quit":
            print("Aborting")
            break

        exists = return_key(db=db, username=target_user)

        if exists is None:
            print('The user doesnt exist')
            continue
        else:
            flag1 = True
            break

    while flag1 is True:
        #NOTE: On this part, allow for a new password to be put then create a function in db_functions to update a value
        ...
def main():
    flag1 = False
    attempts = 0
    while flag1 is False:
        if attempts == 3:
            print("You have exceeded the maximum allowed number of attempts")
            break

        is_auth = authenticate()

        if is_auth is False:
            print("You have not presented the adaquate credentials")
            attempts += 1
        else:
            flag1 = True


    while flag1 is True:
        choice = input("What would you like to do?\n")


    


    

