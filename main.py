from fastapi import FastAPI, Depends,HTTPException
from pydantic import BaseModel, field_validator
import bcrypt
from database.db_functions import return_key,authorize_user
from database.database import get_db

class Request(BaseModel):
    name: str
    type: str
    target: str
    key: str
    @field_validator("type")
    @classmethod
    def check(cls, value):
        options = ["recon_ip_scan"]
        if value not in options:
            raise ValueError("The option selected is not avaliable at present or doesn't exist")


def authenticate(request: Request) -> bool:
    hashed_pass_in_db = return_key(db=Depends(get_db), username=request.name)

    if hashed_pass_in_db is not None:
        hashed_pass_in_db = hashed_pass_in_db["user_key"]
    else:
        hashed_pass_in_db = "dummy".encode()

    byte_pass = request.key.encode()

    check = bcrypt.checkpw(password=byte_pass, hashed_password=hashed_pass_in_db)

    return check

api = FastAPI()



@api.get("/scan")
def scan(request: Request):

    authentication = authenticate(request=request)

    if authentication is False:
        raise HTTPException(
            status_code=401,
            detail="The key and/or name in the http request is invalid")
    
    match request.type:
        case "recon_ip_scan":
            ...
