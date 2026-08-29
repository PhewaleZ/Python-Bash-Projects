from fastapi import FastAPI, Depends,HTTPException
from pydantic import BaseModel, field_validator
import bcrypt
from database.db_functions import return_key,authorize_user
from database.database import get_db
from services.ipinfoAPI import see_own_ip,check_ip
from ipaddress import IPv4Address, IPv6Address
from sqlalchemy.orm import Session

class IPRequest(BaseModel):
    name: str
    scan_type: str
    ip_target: IPv4Address | IPv6Address
    key: str
    @field_validator("scan_type")
    @classmethod
    def check(cls, value):
        options = ["recon_ip_scan", "own_ip"]
        if value not in options:
            raise ValueError("The option selected is not avaliable at present or doesn't exist")

def authorize(request: IPRequest, db: Session) -> bool:
    check = authorize_user(db=db, username=request.name)
    if check is None:
        return False
    else:
        return check["is_admin"]


def authenticate(request: IPRequest, db: Session) -> bool:
    hashed_pass_in_db = return_key(db=db, username=request.name)
    print(f"The retrieved password is:\n{hashed_pass_in_db}")
    if hashed_pass_in_db is None:
        pass_in_db = "dummy".encode()
    else:
        pass_in_db = hashed_pass_in_db["user_key"]
        pass_in_db = pass_in_db.encode()

    byte_pass = request.key.encode()

    check = bcrypt.checkpw(password=byte_pass, hashed_password=pass_in_db)

    return check

def scan_response_template(result: tuple[bool, str|dict]):
    if result[0] is True:
        response = {
            "Result":
            {
                "Status": "Successful",
                "Data":result[1]
            }
        }
    else:
        response ={
            "Result":
            {
                "Status": "Failed",
                "Reason": result[1]
            }
        }

    return response


api = FastAPI(
    title="Cybersecurity API",
    description="This is me validating and improving my understanding of API's",
    version="1.0.0"
)



@api.post("/ipscan")
def scan(request: IPRequest, db:Session = Depends(get_db)):

    authentication = authenticate(request=request, db=db)
    print("It has gone beyond the authentication part")
    if authentication is False:
        raise HTTPException(
            status_code=401,
            detail="The key and/or name in the http request is invalid")
    
    match request.scan_type:
        #This makes use of Ipinfo only
        case "recon_ip_scan":
            print("Its doing the recon scan now")
            result = check_ip(target_ip=request.ip_target)
            return scan_response_template(result=result)
        
        case "own_ip":
            if authorize(request=request, db=db) is False:
                raise HTTPException(
                    status_code=401,
                    detail="You are not authorized to do this"
                )
            else:
                result = see_own_ip()
                return scan_response_template(result=result)
            