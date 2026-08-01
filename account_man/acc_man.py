from sqlalchemy.orm import Session
from ..database.db_functions import add_user
from ..database.db_schema import User
import bcrypt
from ..database.database import SessionLocal, engine
from ..database import db_schema
from ..database.db_schema import Base


def create_user():
    while True:
        proposed_username= input("What is the name of the first user \nNote that spaces will be stripped from the password:\n ").strip()

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