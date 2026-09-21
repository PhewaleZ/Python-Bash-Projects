from fastapi import FastAPI, Depends,HTTPException
from pydantic import BaseModel, field_validator, Field
import bcrypt
from database.db_functions import return_key,authorize_user
from database.database import get_db
from services.ipinfoAPI import see_own_ip,check_ip
from ipaddress import IPv4Address, IPv6Address
from sqlalchemy.orm import Session
from services.virustotal import scan_IP_DOMAIN_VT,scan_file_VT, scan_URL_VT
from services.alienvault import scan_IP_AV,scan_file_AV, scan_url_AV, scan_domain_hostname_AV
from services.abuselpdb import scan_ip_APDB
from typing import Literal

class IPRequest(BaseModel):
    name: str
    scan_type: str
    target_ip: IPv4Address | IPv6Address
    key: str
    ip_id: str = "Not Specified"
    #The option1 attribute is used when a scan using a specific service is requried, its a list of the options
    scan_engine : list = []
    #The report_age attribute is used with abuselpdb for selecting the age of IP reports
    report_age : int = 0
    @field_validator("scan_type")
    @classmethod
    def check_scantype(cls, value):
        options = ["recon_ip_scan", "own_ip", "scan_ip", "custom"]
        if value not in options:
            raise HTTPException(
                status_code=422,
                detail="The selected scan type doesnt exist or is invalid"
            )
        return value
    
    @field_validator("scan_engine")
    @classmethod
    def check_option1(cls, value):
        #Valid options will be placed here
        corrected_options = []
        #If a user wants to just use ipinfo they shoudl do a "recon_ip_scan" scan type
        options = ["abuselpdb", "virustotal", "alienvault"]
        for element in value:
            if element in options:
                corrected_options.append(element)

        if not corrected_options:
            raise HTTPException(
                    status_code=422,
                    detail="The selected scan types do not exist or are invalid"
                        )
        else:
            return corrected_options
    

class FileRequest(BaseModel):
    name: str
    target_hash: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    key: str
    file_id:str = "Not Specified"
    scan_engine: list
    @field_validator("scan_engine")
    @classmethod
    def scantype_check(cls, value):
        corrected_options = []
        options = ["virustotal", "alienvault"]
        for option in value:
            if option in options:
                corrected_options.append(option)

        if not corrected_options:
            raise HTTPException(
                status_code=422,
                detail="No valid engine was specified in the request"
            )
        
        return corrected_options
        
class URLRequestLight(BaseModel):
    name: str
    key: str
    url_id: str="Not Specified"
    target_url: str
    scan_engine: list
    @field_validator("scan_engine")
    @classmethod
    def check_scan_engine(cls, value):
        corrected_options = []
        aval_option = ["virustotal", "alienvault"]
        for element in value:
            if element in aval_option:
                corrected_options.append(element)

        if not corrected_options:
            raise HTTPException(
                status_code=422,
                detail="No valid engine was specified in the request"
            )

        return corrected_options

class URLRequestHeavy(BaseModel):
    name: str
    key: str
    url_id: str="Not Specified"
    target_url: str

class DomainRequest(BaseModel):
    name: str
    key: str
    domain_id: str="Not Specified"
    target_domain: str
    is_hostname: bool = False
    scan_engines: list
    @field_validator("scan_engines")
    @classmethod
    def check_scan_engine(cls, value):
        aval_option = ["alienvault", "virustotal"]
        corrected_options = []
        for element in value:
            if element in aval_option:
                corrected_options.append(element)
        
        if not corrected_options:
            raise HTTPException(
                        status_code=422,
                        detail="No valid engine was specified in the request"
                    )
        
        return corrected_options


def authorize(username: str, db: Session) -> bool:
    check = authorize_user(db=db, username=username)
    if check is None:
        return False
    else:
        return check["is_admin"]


def authenticate(request: IPRequest|FileRequest|URLRequestHeavy|URLRequestLight|DomainRequest, db: Session):
    hashed_pass_in_db = return_key(db=db, username=request.name)
    if hashed_pass_in_db is None:
        pass_in_db = "dummy".encode()
    else:
        pass_in_db = hashed_pass_in_db["user_key"]
        pass_in_db = pass_in_db.encode()

    byte_pass = request.key.encode()

    check = bcrypt.checkpw(password=byte_pass, hashed_password=pass_in_db)

    if check is False:
         raise HTTPException(
                    status_code=401,
                    detail="The key and/or name in the http request is invalid"
                    )


def scan_response_template(result: tuple[bool, str|dict], service: Literal["Ipinfo", "Alienvault", "Virustotal", "AbuselPDB"], scan_type:Literal["IPaddress", "Domain", "URL", "File"], id_detail: str):
    if result[0] is True:
        response = {
            "Result":
            {
                "id": id_detail,
                "service": service,
                "scan_type": scan_type,
                "Status": "Successful",
                "Data":result[1]
            }
        }
    else:
        response ={
            "Result":
            {
                "id": id_detail,
                "service": service,
                "scan_type": scan_type,
                "Status": "Failed",
                "Reason": result[1]
            }
        }

    return response


#The age_option is meant to be used with abuselpdb to specify the age of pulled reports
def ip_scan(target: IPv4Address|IPv6Address , type: Literal["recon_ip_scan", "own_ip", "scan_ip"], is_admin: bool, id_detail: str, age_option=0) -> dict:

    match type:
            case "recon_ip_scan":
                IPINFOresult = check_ip(target_ip=target)
                IPINFOresult_temp = scan_response_template(result=IPINFOresult, service="Ipinfo", scan_type="IPaddress", id_detail=id_detail)
                return {"results": [IPINFOresult_temp]}
            
            case "own_ip":
                if is_admin is False:
                    raise HTTPException(
                        status_code=401,
                        detail="You are not authorized to do this"
                    )
                else:
                    IPINFOresult = see_own_ip()
                    IPINFOresult_temp = scan_response_template(result=IPINFOresult, service='Ipinfo', scan_type="IPaddress", id_detail=id_detail)
                    return {"results": [IPINFOresult_temp]}

            case "scan_ip":
                VTresult = VTscan(scantype="ipaddress", target=target, id_detail=id_detail)
                AVresult = AVscan(scantype="ipaddress", target=target, id_detail=id_detail)
                ABPDBresult = ABPDBscan(target=target, age=age_option, id_detail=id_detail)
                return {"results":[VTresult, AVresult, ABPDBresult]}
    
def VTscan(scantype: Literal["domain", "file", "ipaddress", "url"], target: str|IPv6Address|IPv4Address, id_detail: str):
    match scantype:
        case "ipaddress":
            VTresult = scan_IP_DOMAIN_VT(target_IP_DOMAIN=target, scan_type="IP")
            VTresult_temp = scan_response_template(result=VTresult, service="Virustotal", scan_type="IPaddress", id_detail=id_detail)
            return VTresult_temp
        case "file":
            VTresult = scan_file_VT(file_hash=target,target_file_name=id_detail)
            VTresult_temp = scan_response_template(result=VTresult, service="Virustotal", scan_type="File", id_detail=id_detail)
            return VTresult_temp
        case "url":
            VTresult = scan_URL_VT(target_URL=target)
            VTresult_temp = scan_response_template(result=VTresult, service="Virustotal", scan_type="URL", id_detail=id_detail)
            return VTresult_temp
        case _:
            raise HTTPException(
                status_code=503,
                detail="This service hasnt been implemented et"
            )

def AVscan(scantype: Literal["domain", "file", "ipaddress", "url_light", "url_heavy"], target: str|IPv6Address|IPv4Address, id_detail: str):
    match scantype:
        case "ipaddress":
            AVresult = scan_IP_AV(target_IP=target) # type: ignore
            AVresult_temp = scan_response_template(result=AVresult, service="Alienvault", scan_type="IPaddress", id_detail=id_detail) 
            return AVresult_temp
        case "file":
            AVresult = scan_file_AV(file_hash=target) # type: ignore
            AVresult_temp = scan_response_template(result=AVresult, service="Alienvault", scan_type="File", id_detail=id_detail)
            return AVresult_temp
        case "url_light":
            AVresult = scan_url_AV(target_url=target, scan_type="LIGHT_URL")
            AVresult_temp = scan_response_template(result=AVresult, service="Alienvault", scan_type="URL", id_detail=id_detail)
            return AVresult_temp
        case "url_heavy":
            AVresult = scan_url_AV(target_url=target, scan_type="HEAVY_URL")
            AVresult_temp = scan_response_template(result=AVresult, service="Alienvault", id_detail=id_detail, scan_type="URL")
            return AVresult_temp
        case "domain":
            AVresult = scan_domain_hostname_AV(target_domain=target, is_domain=True)
            AVresult_temp = scan_response_template(result=AVresult, service="Alienvault", id_detail=id_detail, scan_type="Domain")
            return AVresult_temp
        case _:
            raise HTTPException(
                        status_code=503,
                        detail="This service hasnt been implemented et"
                    )
        

#abuselpdb can only do ip address scans
def ABPDBscan(target: IPv4Address|IPv6Address, age: int, id_detail: str):
    ABPDBresult = scan_ip_APDB(target_IP=target, report_age=age)
    ABDBresult_temp = scan_response_template(result=ABPDBresult, service="AbuselPDB", scan_type="IPaddress", id_detail=id_detail)
    return ABDBresult_temp

api = FastAPI(
    title="Cybersecurity API",
    description="This is me validating and improving my understanding of API's",
    version="1.0.0"
)

@api.post("/ipscans")
def scanip(request: IPRequest, db:Session = Depends(get_db)):
    is_admin = False

    authenticate(request=request, db=db)

    if authorize(username=request.name, db=db) is True:
        is_admin = True

    if request.scan_type == "custom":
        results = []
        for service in request.scan_engine:
            match service:
                case "abuselpdb":
                    ABPDBresult = ABPDBscan(target=request.target_ip, age=request.report_age, id_detail=request.ip_id)
                    results.append(ABPDBresult)

                case "virustotal":
                    VTresult = VTscan(scantype="ipaddress", target=request.target_ip, id_detail=request.ip_id)
                    results.append(VTresult)

                case "alienvault":
                    AVresult = AVscan(scantype="ipaddress", target=request.target_ip, id_detail=request.ip_id)
                    results.append(AVresult)

        return {"results": results}
    else:
        return ip_scan(target=request.target_ip, type=request.scan_type, is_admin=is_admin, age_option=request.report_age)  # type: ignore

@api.post("/filescans")
def scanfile(request: FileRequest, db:Session = Depends(get_db)):
    results = []
    authenticate(request=request, db=db)

    for option in request.scan_engine:
        match option:
            case "virustotal":
                VTresult = VTscan(scantype="file", target=request.target_hash, id_detail=request.file_id)
                results.append(VTresult)
            case "alienvault":
                AVresult = AVscan(scantype="file", target=request.target_hash, id_detail=request.file_id)
                results.append(AVresult)

    return {"results": results}

@api.post("/urlscans/lightscans")
def scanurl_light(request: URLRequestLight, db:Session = Depends(get_db)):
    results = []

    authenticate(request=request, db=db)

    for option in request.scan_engine:
        match option:
            case "virustotal":
                VTresult = VTscan(scantype="url", target=request.target_url, id_detail=request.url_id)
                results.append(VTresult)
            case "alienvault":
                AVresult = AVscan(scantype="url_light", target=request.target_url, id_detail=request.url_id)
                results.append(AVresult)

    return {"results": results}

@api.post("/urlscans/heavyscans")
def scanurl_heavy(request: URLRequestHeavy, db: Session = Depends(get_db)):
    authenticate(request=request, db=db)

    AVresult = AVscan(scantype="url_heavy", target=request.target_url, id_detail=request.url_id)

    return {"results": AVresult}

@api.post("/domainscans")
def scandomain(request: DomainRequest, db: Session = Depends(get_db)):
    authenticate(request=request, db=db)

    result = []
    for option in request.scan_engines:
        match option:
            case "alienvault":
                AVresult = AVscan(scantype="domain", target=request.target_domain, id_detail=request.domain_id)
                result.append(AVresult)
            case "virustotal":
                VTresult = VTscan(scantype="domain", target=request.target_domain, id_detail=request.domain_id)
                result.append(VTresult)

    return {"results": result}
            



                
                    


    
