#NOTE: The hostname scanning functionality has been removed, implment its removal here too
#NOTE: Changes the scan_ip_APDB functiion name and gave report_age a default value of 90 on the parameter
from fastapi import FastAPI, Depends,HTTPException
import bcrypt
from database.db_functions import search_user_key,search_user, search_user_id
from database.database import get_db
from services.ipinfoAPI import see_own_ip,check_ip
from ipaddress import IPv4Address, IPv6Address
from sqlalchemy.orm import Session
from services.virustotal import scan_ip_domain_vt,scan_file_vt, scan_url_vt
from services.alienvault import scan_ip_av,scan_file_av, scan_url_av, scan_domain_av
from services.abuselpdb import scan_ip_apdb
from typing import Literal
from pyd_models import IPRequest,FileRequest,URLRequestHeavy,URLRequestLight,DomainRequest
from administrative.logging import create_log

def authorize_user(request: IPRequest|FileRequest|URLRequestHeavy|URLRequestLight|DomainRequest, db: Session) -> bool:
    check = search_user(db=db, username=request.name)
    if check is None:
        return False
    else:
        return check["is_admin"]


def authenticate_user(request: IPRequest|FileRequest|URLRequestHeavy|URLRequestLight|DomainRequest, db: Session):
    hashed_pass_in_db = search_user_key(db=db, username=request.name)

    #NOTE: This is a security feature
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
                ipinfo_result = check_ip(target_ip=target)
                ipinfo_result_temp = scan_response_template(result=ipinfo_result, service="Ipinfo", scan_type="IPaddress", id_detail=id_detail)
                return {"results": [ipinfo_result_temp]}
            
            case "own_ip":
                if is_admin is False:
                    raise HTTPException(
                        status_code=401,
                        detail="You are not authorized to do this"
                    )
                else:
                    ipinfo_result = see_own_ip()
                    ipinfo_result_temp = scan_response_template(result=ipinfo_result, service='Ipinfo', scan_type="IPaddress", id_detail=id_detail)
                    return {"results": [ipinfo_result_temp]}

            case "scan_ip":
                VTresult = VTscan(scantype="ipaddress", target=target, id_detail=id_detail)
                AVresult = AVscan(scantype="ipaddress", target=target, id_detail=id_detail)
                ABPDBresult = ABPDBscan(target=target, age=age_option, id_detail=id_detail)
                return {"results":[VTresult, AVresult, ABPDBresult]}
    
def VTscan(scantype: Literal["domain", "file", "ipaddress", "url"], target: str|IPv6Address|IPv4Address, id_detail: str):
    match scantype:
        case "ipaddress":
            VTresult = scan_ip_domain_vt(target_ip_domain=target, scan_type="IP")
            VTresult_temp = scan_response_template(result=VTresult, service="Virustotal", scan_type="IPaddress", id_detail=id_detail)
            return VTresult_temp
        case "domain":
            VTresult = scan_ip_domain_vt(target_ip_domain=target, scan_type="DOMAIN")
            VTresult_temp = scan_response_template(result=VTresult, service="Virustotal", id_detail=id_detail,scan_type="Domain")
            return VTresult_temp
        case "file":
            assert isinstance(target, str)
            VTresult = scan_file_vt(file_hash=target,target_file_name=id_detail)
            VTresult_temp = scan_response_template(result=VTresult, service="Virustotal", scan_type="File", id_detail=id_detail)
            return VTresult_temp
        case "url":
            assert isinstance(target, str)
            VTresult = scan_url_vt(target_url=target)
            VTresult_temp = scan_response_template(result=VTresult, service="Virustotal", scan_type="URL", id_detail=id_detail)
            return VTresult_temp
        case _:
            raise HTTPException(
                status_code=503,
                detail="This service doesnt exist"
            )

def AVscan(scantype: Literal["domain", "file", "ipaddress", "url_light", "url_heavy"], target: str|IPv6Address|IPv4Address, id_detail: str):
    match scantype:
        case "ipaddress":
            assert isinstance(target, (IPv4Address, IPv6Address))
            AVresult = scan_ip_av(target_ip=target)
            AVresult_temp = scan_response_template(result=AVresult, service="Alienvault", scan_type="IPaddress", id_detail=id_detail) 
            return AVresult_temp
        case "file":
            assert isinstance(target, str)
            AVresult = scan_file_av(file_hash=target)
            AVresult_temp = scan_response_template(result=AVresult, service="Alienvault", scan_type="File", id_detail=id_detail)
            return AVresult_temp
        case "url_light":
            assert isinstance(target, str)
            AVresult = scan_url_av(target_url=target, scan_type="LIGHT_URL")
            AVresult_temp = scan_response_template(result=AVresult, service="Alienvault", scan_type="URL", id_detail=id_detail)
            return AVresult_temp
        case "url_heavy":
            assert isinstance(target, str)
            AVresult = scan_url_av(target_url=target, scan_type="HEAVY_URL")
            AVresult_temp = scan_response_template(result=AVresult, service="Alienvault", id_detail=id_detail, scan_type="URL")
            return AVresult_temp
        case "domain":
            assert isinstance(target, str)
            AVresult = scan_domain_av(target_domain=target)
            AVresult_temp = scan_response_template(result=AVresult, service="Alienvault", id_detail=id_detail, scan_type="Domain")
            return AVresult_temp
        case _:
            raise HTTPException(
                        status_code=503,
                        detail="This service doesnt exist"
                    )
        

#abuselpdb can only do ip address scans
def ABPDBscan(target: IPv4Address|IPv6Address, age: int, id_detail: str):
    ABPDBresult = scan_ip_apdb(target_ip=target, report_age=age)
    ABDBresult_temp = scan_response_template(result=ABPDBresult, service="AbuselPDB", scan_type="IPaddress", id_detail=id_detail)
    return ABDBresult_temp

api = FastAPI(
    title="Cybersecurity API",
    description="This is me validating and improving my understanding of API's",
    version="1.0.0"
)

@api.post("/ipscans")
def scan_ip(request: IPRequest, db:Session = Depends(get_db)):
    print(f"The request looks like {request}")
    is_admin = False
    authenticate_user(request=request, db=db)
    
    user_id = search_user_id(db=db, target_username=request.name)
    assert user_id is not None
    if authorize_user(request=request, db=db) is True:
        is_admin = True

    if request.scan_type == "custom":
        results = []
        for service in request.scan_engine:
            print("It is matching the services now")
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

        create_log(log_type="scan_result", log_detail="standard_scan", subject_name=request.name, subject_id=user_id, db=db, scan_result=results) # pyright: ignore[reportArgumentType]

        return {"results": results}
    else:
        results = ip_scan(target=request.target_ip, type=request.scan_type, is_admin=is_admin, age_option=request.report_age)  # type: ignore
        
        create_log(log_type="scan_result", log_detail="standard_scan", subject_name=request.name, subject_id=user_id, db=db, scan_result=results)

        return results

@api.post("/filescans")
def scan_file(request: FileRequest, db:Session = Depends(get_db)):
    results = []
    authenticate_user(request=request, db=db)
    user_id = search_user_id(db=db, target_username=request.name)
    assert user_id is not None
    for option in request.scan_engine:
        match option:
            case "virustotal":
                VTresult = VTscan(scantype="file", target=request.target_hash, id_detail=request.file_id)
                results.append(VTresult)
            case "alienvault":
                AVresult = AVscan(scantype="file", target=request.target_hash, id_detail=request.file_id)
                results.append(AVresult)

    create_log(log_type="scan_result", log_detail="standard_scan", subject_name=request.name, subject_id=user_id, db=db, scan_result=results)
    
    return {"results": results}

@api.post("/urlscans/lightscans")
def scanurl_light(request: URLRequestLight, db:Session = Depends(get_db)):
    results = []
    authenticate_user(request=request, db=db)

    user_id = search_user_id(db=db, target_username=request.name)

    assert user_id is not None
    for option in request.scan_engine:
        match option:
            case "virustotal":
                VTresult = VTscan(scantype="url", target=request.target_url, id_detail=request.url_id)
                results.append(VTresult)
            case "alienvault":
                AVresult = AVscan(scantype="url_light", target=request.target_url, id_detail=request.url_id)
                results.append(AVresult)

    create_log(log_type="scan_result", log_detail="standard_scan", subject_name=request.name, subject_id=user_id, db=db, scan_result=results)

    return {"results": results}

@api.post("/urlscans/heavyscans")
def scanurl_heavy(request: URLRequestHeavy, db: Session = Depends(get_db)):
    authenticate_user(request=request, db=db)

    user_id = search_user_id(db=db, target_username=request.name)
    assert user_id is not None

    AVresult = AVscan(scantype="url_heavy", target=request.target_url, id_detail=request.url_id)

    create_log(log_type="scan_result", log_detail="standard_scan", subject_name=request.name, subject_id=user_id, db=db, scan_result=AVresult)

    return {"results": AVresult}

@api.post("/domainscans")
def scan_domain(request: DomainRequest, db: Session = Depends(get_db)):
    authenticate_user(request=request, db=db)

    user_id = search_user_id(db=db, target_username=request.name)
    assert user_id is not None

    results = []
    for option in request.scan_engines:
        match option:
            case "alienvault":
                AVresult = AVscan(scantype="domain", target=request.target_domain, id_detail=request.domain_id)
                results.append(AVresult)
            case "virustotal":
                VTresult = VTscan(scantype="domain", target=request.target_domain, id_detail=request.domain_id)
                results.append(VTresult)

    create_log(log_type="scan_result", log_detail="standard_scan", subject_name=request.name, subject_id=user_id, db=db, scan_result=results)

    return {"results": results}
            



                
                    


    
