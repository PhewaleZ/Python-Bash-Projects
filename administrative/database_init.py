from database.db_schema import User,Base,Log
import bcrypt
from database.database import SessionLocal, engine
from os import getenv
from sqlalchemy.exc import IntegrityError
from sys import exit

class LengthError(BaseException):
    pass

def initialize_database():
    try:
        username = getenv("INITIAL_USERNAME")
        password= getenv("INITIAL_KEY")

        if not username or not password:
            print("Please ensure all relevant environmental variable have been filled out, username and/or password is missing")
            raise Exception

        if len(username) >= 15:
            raise LengthError
        
    except Exception as err:
        print(f"The database initialization script failed: {err}\n Please ensure environmental variables have been properly filled out")
        exit(1)

    except LengthError:
        print(f"The database initialization script failed:The username is too long, The amount of characters should be below 15 ")
        exit(1)

    byte_password = password.encode()
    salt = bcrypt.gensalt()
    password_hash = bcrypt.hashpw(password=byte_password, salt=salt)
    password_hash = password_hash.decode()

    Base.metadata.create_all(bind=engine)

    db = SessionLocal()

    try:
        user = User(username=username,
            user_key=password_hash,
            is_admin=True)

        db.add(user)
        db.commit()

    #This part prevents any error caused by the intended "first account" already existing
    except IntegrityError:
        pass
    finally:
        db.close()

    print("Tables have been created")
if "__main__" == __name__:
    initialize_database()