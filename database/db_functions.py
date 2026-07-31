from db_schema import User, Scan
from sqlalchemy import select

def add_user(user_obj: User):
    ses