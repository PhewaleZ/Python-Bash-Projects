from .db_schema import User, Log
from sqlalchemy.orm import Session
from sqlalchemy import delete, update

def add_user(db: Session, user_obj: User):
    db.add(user_obj)
    db.commit()
    db.refresh(user_obj)

#This will return the stored hash of that users password
def search_user_key(db: Session, username: str):
    query = db.query(User.user_key).where(User.username==username)
    result = db.execute(query)
    result = result.scalar_one_or_none()

    return result

#This returns the field in the users "is_admin" column
def retrieve_user_authorization(db: Session, username: str):
    query = db.query(User.is_admin).where(User.username==username)
    result = db.execute(query)
    result = result.scalar_one_or_none

    return result


def delete_user(db: Session, target_username: str):
    query = delete(User).where(User.username==target_username)
    db.execute(query)
    db.commit()


def change_user_key(db: Session, target_username: str, new_key: str):
    query = update(User).where(User.username == target_username).values(user_key=new_key)
    db.execute(query)
    db.commit()

def change_user_privilege(db:Session, target_username: str, admn_privilege: bool):
    query = update(User).where(User.username == target_username).values(is_admin=admn_privilege)
    db.execute(query)
    db.commit()

def list_admin_users(db:Session):
    query = db.query(User.username, User.user_id).where(User.is_admin == True)
    result = db.execute(query)
    list_of_users = result.all()

    return list_of_users

def search_user_id(db:Session, target_username: str):
    query = db.query(User.user_id).where(User.username == target_username)
    result = db.execute(query)
    result = result.scalar()

    return result

def record_log(db:Session, log_obj: Log):
    db.add(log_obj)
    db.commit()
    db.refresh(log_obj)

def retrieve_all_logs(db:Session):
    query = db.query(Log.data, Log.timestamp, Log.user_id, Log.log_id)
    result = db.execute(query)
    result = result.mappings().all()

    return result

def retrieve_user_logs(db:Session, target_userid:str):
    query = db.query(Log.data, Log.timestamp, Log.user_id, Log.log_id).where(Log.user_id == target_userid)
    result = db.execute(query)
    result = result.mappings().all()

    return result