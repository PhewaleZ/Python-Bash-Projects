from database.db_functions import add_user, authorize_user, return_key
from database.database import SessionLocal
import bcrypt

options = ["y", "n"]

def authenticate():
    username = input("Username: ")
    password = input("Password: ")

    db = SessionLocal()

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
    db = SessionLocal()
    while True:

        prop_username = input("What is the proposed username of the user?\n")
        #The return key function is used as if None is returned by the func, then the username doesnt exist

        exists=return_key(db=db, username=prop_username)

        if exists is not None:
            print("The proposed username already exists!")
            continue

        prop_key = input("What is the proposed key of the user?\n")

        confirm = input(f"Can you confirm {prop_key}? [y/n]").lower()

        if confirm not in options:
            print("select a valid option")
            continue

        if confirm =='n':
            continue
        else:
            flag1 = True
            prop_key = prop_key.encode()
            salt = bcrypt.gensalt()
            key = bcrypt.hashpw(password=prop_key, salt=salt)
            key = key.decode()
            break

    while flag1 is True:
        print("You may input 'quit' to abort")
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
        fin_confirm = input("can you confirm the above credentials?: [y/n]").lower()

        if fin_confirm not in options:
            print("Select a valid option!")
            continue

        #The final step is to write to the database



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


    


    

