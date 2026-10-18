from database.db_schema import User,Base,Log
import bcrypt
from database.database import SessionLocal, engine

def main():
    while True:
        conf = input("Would you like to create the relevant tables, \nIf the tables exist then nothing is done and the existing table wont be affected, [n/y]?").lower()

        match conf:
            case "y":
                initialize_database()
                break
            case "n":
                print("Aborting")
                break
            case "yes":
                initialize_database()
                break
            case "no":
                print("Aborting")
                break
            case _:
                print("select a valid option!")
                continue
        
def initialize_database():
    while True:
        proposed_username= input("What is the name of the first user \nNote that spaces will be stripped from the username:\n ").strip()

        confirmation = input(f"Can you confirm the username, {proposed_username}? [y/n]:")

        if confirmation.lower() != 'y':
            continue
        else:
            break

    while True:
        proposed_pass = input("What is the password you would like to input?\nNote that spaces will be stripped from the password:\n ").strip()
        confirmation = input(f"Can you confirm the password, {proposed_pass}? [y/n]:")
        if confirmation.lower() != 'y':
            continue
        else:
            break

    byte_password = proposed_pass.encode()
    salt = bcrypt.gensalt()
    password_hash = bcrypt.hashpw(password=byte_password, salt=salt)
    password_hash = password_hash.decode()

    user = User(username=proposed_username,
                user_key=password_hash,
                is_admin=True)

    Base.metadata.create_all(bind=engine)

    db = SessionLocal()

    try:
        user = User(username=proposed_username,
            user_key=password_hash,
            is_admin=True)

        db.add(user)
        db.commit()

    finally:
        db.close()

if "__main__" == __name__:
    main()