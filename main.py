from fastapi import FastAPI, Depends,HTTPException
from pydantic import BaseModel, field_validator
import bcrypt
from database.db_functions import return_key,authorize_user
from database.database import get_db
from services.ipinfoAPI import see_own_ip,check_ip
from ipaddress import IPv4Address, IPv6Address
from sqlalchemy.orm import Session
from .services.virustotal import scan_IP_DOMAIN_VT
from .services.alienvault import scan_IP_AV
from .services.abuselpdb import scan_ip_APDB
from typing import Literal
class IPRequest(BaseModel):
    name: str
    scan_type: str
    ip_target: IPv4Address | IPv6Address
    key: str
    #The option1 attribute is used when a scan using a specific service is requried
    option1 : str
    #The option2 attribute is used with abuselpdb for selecting the age of IP reports
    option2 : int = 0
    #NOTE: Make changes to this as more features get added
    @field_validator("scan_type")
    @classmethod
    def check(cls, value):
        print("the scan type is being checked")
        options = ["recon_ip_scan", "own_ip", "scan_ip"]
        if value not in options:
            raise HTTPException(
                status_code=422,
                detail="The selected scan type doesnt exist or is invalid"
            )
        return value

def authorize(request: IPRequest, db: Session) -> bool:
    check = authorize_user(db=db, username=request.name)
    if check is None:
        return False
    else:
        return check["is_admin"]


def authenticate(request: IPRequest, db: Session) -> bool:
    hashed_pass_in_db = return_key(db=db, username=request.name)
    if hashed_pass_in_db is None:
        pass_in_db = "dummy".encode()
    else:
        pass_in_db = hashed_pass_in_db["user_key"]
        pass_in_db = pass_in_db.encode()

    byte_pass = request.key.encode()

    check = bcrypt.checkpw(password=byte_pass, hashed_password=pass_in_db)

    return check

def scan_response_template(result: tuple[bool, str|dict], service: Literal["Ipinfo", "Alienvault", "Virustotal", "AbuselPDB"]):
    if result[0] is True:
        response = {
            "Result":
            {
                "service": service,
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

    if authenticate(request=request, db=db) is False:
        raise HTTPException(
            status_code=401,
            detail="The key and/or name in the http request is invalid")

    match request.scan_type:
        case "recon_ip_scan":
            IPINFOresult = check_ip(target_ip=request.ip_target)
            IPINFOresult_temp = scan_response_template(result=IPINFOresult, service="Ipinfo")
            return {"results": [IPINFOresult_temp]}
        
        case "own_ip":
            if authorize(request=request, db=db) is False:
                raise HTTPException(
                    status_code=401,
                    detail="You are not authorized to do this"
                )

        case "scan_ip":
            VTresult = scan_IP_DOMAIN_VT(target_IP_DOMAIN=request.ip_target, scan_type="IP")
            VTresult_temp = scan_response_template(result=VTresult, service="Virustotal")
            AVresult = scan_IP_AV(target_IP=request.ip_target)
            AVresult_temp = scan_response_template(result=AVresult, service="Alienvault")
            APDBresult = scan_ip_APDB(target_IP=request.ip_target, report_age=request.option2)
            APDBresult_temp = scan_response_template(result=APDBresult, service="AbuselPDB")
            return {"results":[VTresult_temp, AVresult_temp, APDBresult_temp]}