from database.db_functions import add_user, delete_user, return_key, change_user_password, authorize_user, change_user_privilege, list_admin_users
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

    return username if is_auth is True else None

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
        is_priv = input("does this user have administrative privileges?[y/n]: ").lower()

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
        confirm = input("can you confirm the above credentials?[y/n]: ").lower()

        if confirm not in options:
            print("Select a valid option!")
            continue

        if confirm == "n":
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
        confirm = input(f"Can you confirm that the account: {target_user}, is to be deleted? [y/n]: ").lower()

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
        target_username = input("What is the name of the account to have its password changed?:\n")

        if target_username.lower() == "quit":
            print("Aborting")
            break

        exists = return_key(db=db, username=target_username)

        if exists is None:
            print('The user doesnt exist')
            continue
        else:
            flag1 = True
            break

    while flag1 is True:
        #NOTE: On this part, allow for a new password to be put then create a function in db_functions to update a value
        print(abort_opt)
        new_password = input("What is the proposed new password?\n:")

        if new_password.lower() == "quit":
            print("Aborting")
            break

        confirm = input(f"Can you confirm the new password: {new_password} [y/n]?: ").lower()

        if confirm not in options:
            print("Select a valid option")
            continue

        if confirm == "n":
            continue
        else:
            change_user_password(db=db, target_username=target_username, new_password=new_password)
            print("The users password has been changed")
            break

def list_administrators():
    administrators=list_admin_users(db=db)
    admin_counter = 0
    for admin in administrators:
        admin_counter += 1
        print("The list of admins is as follows")
        print(f"User ID | Username ")
        print(f"{admin.user_id}  |  {admin.username}")

    print(f"\nThe number of administrators is: {admin_counter}")

#This function changes the privilages of an account
def change_priv(logged_in_user:str):
    flag1 = False
    while True:
        print(abort_opt)
        target_username = input("What is the username of the account to have its privileges changed?\n")

        if target_username == logged_in_user:
            print("You cant change your own privileges")

        if target_username.lower() == "quit":
            print("Aborting")
            break

        exists = return_key(db=db, username=target_username)

        if exists is None:
            print("The user doesnt exist")
            continue
        else:
            flag1 = True
            is_admin = authorize_user(db=db, username=target_username)
            
            print("The user is an administrator" if is_admin["is_admin"] is True else "This user is not an administrator") # pyright: ignore[reportOptionalSubscript] This error wont occur as it is already checked if the user exists or not
            break

    while flag1 is True:

        new_priv = input("Should the user have administrative privileges [y/n]").lower()

        if new_priv not in options:
            print("select a valid option")
            continue
        elif new_priv == "n":
            change_user_privilege(db=db, target_username=target_username, admn_priv=False)
        else:
            change_user_privilege(db=db, target_username=target_username, admn_priv=True)

        print("The users administrative privilages have been changed")

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
        choice = input("What would you like to do?")

