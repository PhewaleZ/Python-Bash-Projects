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
    #The option1 attribute is used when a scan using a specific service is requried, its a list of the options
    option1 : list = []
    #The option2 attribute is used with abuselpdb for selecting the age of IP reports
    option2 : int = 0
    #NOTE: Make changes to this as more features get added
    @field_validator("scan_type")
    @classmethod
    def check_scan_type(cls, value):
        options = ["recon_ip_scan", "own_ip", "scan_ip", "custom"]
        if value not in options:
            raise HTTPException(
                status_code=422,
                detail="The selected scan type doesnt exist or is invalid"
            )
        return value
    
    @field_validator("option1")
    @classmethod
    def check_option1(cls, value):
        #Valid options will be placed here
        corrected_options = []
        #This value is used to ensure that at least one of the options chosen by the user is a valid service
        is_min = False
        #If a user wants to just use ipinfo they shoudl do a "recon_ip_scan" scan type
        options = ["abuselpdb", "virustotal", "alienvault"]
        for element in value:
            if element in options:
                is_min = True
                corrected_options.append(element)

        if is_min is False:
            raise HTTPException(
                    status_code=422,
                    detail="The selected scan types do not exist or are invalid"
                        )
        else:
            return corrected_options
    

def authorize(username: str, db: Session) -> bool:
    check = authorize_user(db=db, username=username)
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
                "service": service,
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

#The age_option is meant to be used with abuselpdb to specify the age of pulled reports
def ip_scan(target: IPv4Address|IPv6Address , type: Literal["recon_ip_scan", "own_ip", "scan_ip"], is_admin: bool, age_option=0) -> dict:

    match type:
            case "recon_ip_scan":
                IPINFOresult = check_ip(target_ip=target)
                IPINFOresult_temp = scan_response_template(result=IPINFOresult, service="Ipinfo")
                return {"results": [IPINFOresult_temp]}
            
            case "own_ip":
                if is_admin is False:
                    raise HTTPException(
                        status_code=401,
                        detail="You are not authorized to do this"
                    )
                else:
                    IPINFOresult = see_own_ip()
                    IPINFOresult_temp = scan_response_template(result=IPINFOresult, service='Ipinfo')
                    return {"results": [IPINFOresult_temp]}

            case "scan_ip":
                VTresult = VTscan(scantype="ipaddress", target=target)
                AVresult = AVscan(scantype="ipaddress", target=target)
                ABPDBresult = ABPDBscan(target=target, age=age_option)
                return {"results":[VTresult, AVresult, ABPDBresult]}
    
def VTscan(scantype: Literal["domain", "file", "ipaddress"], target: str|IPv6Address|IPv4Address):
    match scantype:
        case "ipaddress":
            VTresult = scan_IP_DOMAIN_VT(target_IP_DOMAIN=target, scan_type="IP")
            VTresult_temp = scan_response_template(result=VTresult, service="Virustotal")
            return VTresult_temp
        case _:
            raise HTTPException(
                status_code=503,
                detail="This service hasnt been implemented et"
            )

def AVscan(scantype: Literal["domain", "file", "ipaddress"], target: str|IPv6Address|IPv4Address):
    match scantype:
        case "ipaddress":
            AVresult = scan_IP_AV(target_IP=target) # type: ignore
            AVresult_temp = scan_response_template(result=AVresult, service="Alienvault") 
            return AVresult_temp

#abuselpdb can only do ip address scans
def ABPDBscan(target: IPv4Address|IPv6Address, age: int):
    ABPDBresult = scan_ip_APDB(target_IP=target, report_age=age)
    ABDBresult_temp = scan_response_template(result=ABPDBresult, service="AbuselPDB")
    return ABDBresult_temp

@api.post("/ipscan")
def scan(request: IPRequest, db:Session = Depends(get_db)):
    is_admin = False

    if authenticate(request=request, db=db) is False:
        raise HTTPException(
            status_code=401,
            detail="The key and/or name in the http request is invalid"
            )

    if authorize(username=request.name, db=db) is True:
        is_admin = True

    if request.scan_type == "custom":
        results = []
        for service in request.option1:
            match service:
                case "abuselpdb":
                    ABPDBresult = ABPDBscan(target=request.ip_target, age=request.option2)
                    results.append(ABPDBresult)

                case "virustotal":
                    VTresult = VTscan(scantype="ipaddress", target=request.ip_target)
                    results.append(VTresult)

                case "alienvault":
                    AVresult = AVscan(scantype="ipaddress", target=request.ip_target)
                    results.append(AVresult)

        return {"results": results}
    else:
        return ip_scan(target=request.ip_target, type=request.scan_type, is_admin=is_admin, age_option=request.option2)  # type: ignore

                
                    


    
