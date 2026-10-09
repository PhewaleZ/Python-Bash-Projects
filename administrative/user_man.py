import bcrypt
from database.db_schema import User
from database.db_functions import add_user, delete_user, return_key, change_user_password, authorize_user, change_user_privilege, list_admin_users
from database.database import SessionLocal

options = ["y", "n"]
db = SessionLocal()
abort_opt = "You may input 'quit' to abort"

def hash_password(password):
    byte_prop_key = password.encode()
    salt = bcrypt.gensalt()
    key = bcrypt.hashpw(password=byte_prop_key, salt=salt)
    key = key.decode()

    return key

#This function returns a tuple, if the users account exists then regardless of their authorization, a boolean stating if they have admin privilege is returns and the second index is their username
def authenticate_authorize():
    username = input("Username: ")
    password = input("Password: ")

    result = return_key(db=db, username=username)
    if result is None:
        password_in_db = "dummy".encode()
    else:
        password_in_db = result["user_key"].encode()

    password = password.encode()
    is_authenticated = bcrypt.checkpw(password=password, hashed_password=password_in_db)

    if is_authenticated is False:
        return False, None

    is_authorized = authorize_user(db=db, username=username)

    assert is_authorized is not None

    if is_authorized["is_admin"] is False:
        print("This user does not have adaquate authorization")
        return False, username
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
        prop_username = input("What is the proposed username of the user?\n").lower()
        #The return key function is used as if None is returned by the func, then the username doesnt exist

        if prop_username == "quit":
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
            key = hash_password(password=prop_key)
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
        print("NOTE: The username field will always be set to lowercase")
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
            hashed_key = hash_password(password=new_password)
            change_user_password(db=db, target_username=target_username, new_password=hashed_key)
            print("The users password has been changed")
            break

def list_administrators():
    administrators=list_admin_users(db=db)
    admin_counter = 0
    print("The list of admins is as follows:")
    print(f"User ID | Username ")
    for admin in administrators:
        admin_counter += 1
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
            break

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
        print(abort_opt)
        new_priv = input("Should the user have administrative privileges [y/n]: ").lower()

        if new_priv == "quit":
            print("Aborting")
            break

        if new_priv not in options:
            print("select a valid option")
            continue
        elif new_priv == "n":
            change_user_privilege(db=db, target_username=target_username, admn_priv=False)
        else:
            change_user_privilege(db=db, target_username=target_username, admn_priv=True)

        print("The users administrative privilages have been changed")
        break

def main():
    flag1 = False
    attempts = 0
    logged_in_user = ""
    while True:
        if attempts == 3:
            print("You have exceeded the maximum allowed number of attempts")
            break

        is_allowed = authenticate_authorize()

        if is_allowed[0] is False:
            print("You have not presented the adaquate credentials")
            #NOTE: in the future, logging will be implemented therefore storing the failed log in attempt will be userful
            logged_in_user = is_allowed[1]
            attempts += 1
        else:
            logged_in_user = is_allowed[1]
            flag1 = True
            break

        
    while flag1 is True:
        #This point of the code will not be reached unless the user is authenticated and autorized
        assert logged_in_user is not None
        try:
            print("1. Add a user. \n2. Remove a user. \n3. Change a users password. \n4. Change a Users privileges. \n5. Show all current administrators. \nInput '0' to exit.")
            choice = int(input("What would you like to do?: "))
        except ValueError:
            print("Select a valid number")
            continue

        match choice:
            case 1: create_user()
            case 2: remove_user()
            case 3: change_password()
            case 4: change_priv(logged_in_user=logged_in_user)
            case 5: list_administrators()
            case 0: 
                print("Exiting")
                break
            case _: print("Select a valid choice")

if __name__ == "__main__":
    main()
