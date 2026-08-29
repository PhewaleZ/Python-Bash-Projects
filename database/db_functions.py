from .db_schema import User
from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy import delete

#In this function a database connection is established by adding Session as a type hint
#The add method will add the user object into the database
#The commit method will finalize the addition
#the refresh method will update the database values
def add_user(db: Session, user_obj: User):
    db.add(user_obj)
    db.commit()
    db.refresh(user_obj)

#This will return the stored hash of that users password
def return_key(db: Session, username: str):
    query = db.query(User.user_key).where(User.username==username)
    key = db.execute(query).mappings()
    key = key.first()

    return key

#This returns the field in the users "is_admin" column
def authorize_user(db: Session, username):
    query = db.query(User.is_admin).where(User.username==username)
    result = db.execute(query).mappings()
    result = result.first()

    return result


def delete_user(db: Session, target_username):
    query = delete(User).where(User.username==target_username)
    db.execute(query)
    db.commit()

