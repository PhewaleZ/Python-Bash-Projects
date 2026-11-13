from database.db_schema import User,Base,Log
import bcrypt
from database.database import SessionLocal, engine
from os import getenv

def initialize_database():
    username = getenv("INITIAL_USERNAME")
    password= getenv("INITIAL_PASSWORD")

    if not username or not password:
        print("Please ensure all relevant environmental variable have been filled out, username and/or password is missing")
        return
    
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

    finally:
        db.close()

    print("Tables have been created")
if "__main__" == __name__:
    initialize_database()