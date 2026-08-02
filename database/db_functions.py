from db_schema import User
from sqlalchemy import select
from sqlalchemy.orm import Session


#In this function a database connection is established by adding Session as a type hint
#The add method will add the user object into the database
#The commit method will finalize the addition
#the refresh method will update the database values
def add_user(db: Session, user_obj: User):
    db.add(user_obj)
    db.commit()
    db.refresh(user_obj)

def return_key(db: Session, user_name: str):
    query = db.query(User.user_key).where(User.username==user_name)
    key = db.execute(query).mappings()
    key = key.first()

    return key

def database_check(db: Session) -> str|None:
    ...
