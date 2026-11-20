from fastapi import FastAPI, Depends,HTTPException, Security
from fastapi.security import APIKeyHeader
import bcrypt
from database.db_functions import search_user_key, search_user_id
from database.database import get_db
from services.ipinfoAPI import Ipinfoscan
from ipaddress import IPv4Address, IPv6Address
from sqlalchemy.orm import Session
from services.virustotal import scan_ip_domain_vt,scan_file_vt, scan_url_vt
from services.alienvault import scan_ip_av,scan_file_av, scan_url_av, scan_domain_av
from services.abuselpdb import scan_ip_apdb
from typing import Literal, Any
from pyd_models import IPRequest,FileRequest,URLRequestHeavy,URLRequestLight,DomainRequest
from administrative.logging import create_log
import httpx

def authenticate_user(request: IPRequest|FileRequest|URLRequestHeavy|URLRequestLight|DomainRequest, APIKey: str,db: Session):
    #NOTE: The keys are stored as strings in the database so encoding is necessary
    hashed_key_in_db = search_user_key(db=db, username=request.username)
    #NOTE: This is a security feature
    if hashed_key_in_db is None:
        salt = bcrypt.gensalt()
        key_in_db = bcrypt.hashpw(password="dummy".encode(), salt=salt)
    else:
        key_in_db = hashed_key_in_db.encode() # pyright: ignore[reportAttributwAccessIssue]

    byte_pass = APIKey.encode()
    check = bcrypt.checkpw(password=byte_pass, hashed_password=key_in_db)
    
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
    
async def VTscan(scantype: Literal["domain", "file", "ipaddress", "url"], target: str|IPv6Address|IPv4Address, id_detail: str, httpxclient: httpx.AsyncClient):
    match scantype:
        case "ipaddress":
            VTresult = await scan_ip_domain_vt(target_ip_domain=target, scan_type="IP", httpxclient=httpxclient)
            VTresult_temp = scan_response_template(result=VTresult, service="Virustotal", scan_type="IPaddress", id_detail=id_detail)
            return VTresult_temp
        case "domain":
            VTresult = await scan_ip_domain_vt(target_ip_domain=target, scan_type="DOMAIN", httpxclient=httpxclient)
            VTresult_temp = scan_response_template(result=VTresult, service="Virustotal", id_detail=id_detail,scan_type="Domain")
            return VTresult_temp
        case "file":
            assert isinstance(target, str)
            VTresult = await scan_file_vt(file_hash=target,target_file_name=id_detail, httpxclient=httpxclient)
            VTresult_temp = scan_response_template(result=VTresult, service="Virustotal", scan_type="File", id_detail=id_detail)
            return VTresult_temp
        case "url":
            assert isinstance(target, str)
            VTresult = await scan_url_vt(target_url=target, httpxclient=httpxclient)
            VTresult_temp = scan_response_template(result=VTresult, service="Virustotal", scan_type="URL", id_detail=id_detail)
            return VTresult_temp
        case _:
            raise HTTPException(
                status_code=503,
                detail="This service doesnt exist"
            )

async def AVscan(scantype: Literal["domain", "file", "ipaddress", "url_light", "url_heavy"], target: str|IPv6Address|IPv4Address, id_detail: str, httpxclient: httpx.AsyncClient):
    match scantype:
        case "ipaddress":
            assert isinstance(target, (IPv4Address, IPv6Address))
            AVresult = await scan_ip_av(target_ip=target, httpxclient=httpxclient)
            AVresult_temp = scan_response_template(result=AVresult, service="Alienvault", scan_type="IPaddress", id_detail=id_detail) 
            return AVresult_temp
        case "file":
            assert isinstance(target, str)
            AVresult = await scan_file_av(file_hash=target, httpxclient=httpxclient)
            AVresult_temp = scan_response_template(result=AVresult, service="Alienvault", scan_type="File", id_detail=id_detail)
            return AVresult_temp
        case "url_light":
            assert isinstance(target, str)
            AVresult = await scan_url_av(target_url=target, scan_type="LIGHT_URL", httpxclient=httpxclient)
            AVresult_temp = scan_response_template(result=AVresult, service="Alienvault", scan_type="URL", id_detail=id_detail)
            return AVresult_temp
        case "url_heavy":
            assert isinstance(target, str)
            AVresult = await scan_url_av(target_url=target, scan_type="HEAVY_URL", httpxclient=httpxclient)
            AVresult_temp = scan_response_template(result=AVresult, service="Alienvault", id_detail=id_detail, scan_type="URL")
            return AVresult_temp
        case "domain":
            assert isinstance(target, str)
            AVresult = await scan_domain_av(target_domain=target, httpxclient=httpxclient)
            AVresult_temp = scan_response_template(result=AVresult, service="Alienvault", id_detail=id_detail, scan_type="Domain")
            return AVresult_temp
        case _:
            raise HTTPException(
                        status_code=503,
                        detail="This service doesnt exist"
                    )
        
async def ABPDBscan(target: IPv4Address|IPv6Address, age: int, id_detail: str, httpxclient: httpx.AsyncClient):
    ABPDBresult = await scan_ip_apdb(target_ip=target, report_age=age, httpxclient=httpxclient)
    ABDBresult_temp = scan_response_template(result=ABPDBresult, service="AbuselPDB", scan_type="IPaddress", id_detail=id_detail)
    return ABDBresult_temp

async def IPinfoscan(target: IPv4Address|IPv6Address, id_detail: str, httpxclient: httpx.AsyncClient):
    IPinforesult =  await Ipinfoscan(target_ip=target, httpxclient=httpxclient)
    IPinforesult_temp = scan_response_template(result=IPinforesult, service="Ipinfo", scan_type="IPaddress", id_detail=id_detail)
    return IPinforesult_temp

api = FastAPI(
    title="Cybersecurity API",
    description="A cybersecurity IOC lookup API project made by 'Phewale Zembe'",
    version="1.0"
)

@api.post("/ipscans")
async def scan_ip(request: IPRequest, APIKey=Security(APIKeyHeader(name="X-API-KEY")),db:Session = Depends(get_db)):
    results = []
    authenticate_user(request=request, db=db, APIKey=APIKey)
    user_id = search_user_id(db=db, target_username=request.username)
    assert user_id is not None
    async with httpx.AsyncClient() as httpxclient:
        #NOTE: An IPINFO result is always returned by this endpoint as it is free and has very few restrictions
        IPinforesult= await IPinfoscan(target=request.target_ip,id_detail=request.ip_id, httpxclient=httpxclient)
        results.append(IPinforesult)

        for service in request.scan_engines:
            match service:
                case "abuselpdb":
                    ABPDBresult = await ABPDBscan(target=request.target_ip, age=request.report_age, id_detail=request.ip_id, httpxclient=httpxclient)
                    results.append(ABPDBresult)

                case "virustotal":
                    VTresult = await VTscan(scantype="ipaddress", target=request.target_ip, id_detail=request.ip_id, httpxclient=httpxclient)
                    results.append(VTresult)

                case "alienvault":
                    AVresult = await AVscan(scantype="ipaddress", target=request.target_ip, id_detail=request.ip_id, httpxclient=httpxclient)
                    results.append(AVresult)

    create_log(log_type="scan_result", log_detail="standard_scan", subject_name=request.username, subject_id=user_id, db=db,scan_result=results)

    return {"results": results}


@api.post("/filescans")
async def scan_file(request: FileRequest, APIKey=Security(APIKeyHeader(name="X-API-KEY")),db: Session = Depends(get_db)):
    results = []
    authenticate_user(request=request, db=db, APIKey=APIKey)
    user_id = search_user_id(db=db, target_username=request.username)
    assert user_id is not None
    async with httpx.AsyncClient() as httpxclient:
        for option in request.scan_engines:
            match option:
                case "virustotal":
                    VTresult = await VTscan(scantype="file", target=request.target_hash, id_detail=request.file_id, httpxclient=httpxclient)
                    results.append(VTresult)
                case "alienvault":
                    AVresult = await AVscan(scantype="file", target=request.target_hash, id_detail=request.file_id, httpxclient=httpxclient)
                    results.append(AVresult)

    create_log(log_type="scan_result", log_detail="standard_scan", subject_name=request.username, subject_id=user_id, db=db, scan_result=results)
    
    return {"results": results}

@api.post("/urlscans/lightscans")
async def scanurl_light(request: URLRequestLight,APIKey=Security(APIKeyHeader(name="X-API-KEY")), db:Session = Depends(get_db)):
    results = []
    authenticate_user(request=request, db=db, APIKey=APIKey)

    user_id = search_user_id(db=db, target_username=request.username)

    assert user_id is not None
    async with httpx.AsyncClient() as httpxclient:
        for option in request.scan_engines:
            match option:
                case "virustotal":
                    VTresult = await VTscan(scantype="url", target=request.target_url, id_detail=request.url_id, httpxclient=httpxclient)
                    results.append(VTresult)
                case "alienvault":
                    AVresult = await AVscan(scantype="url_light", target=request.target_url, id_detail=request.url_id, httpxclient=httpxclient)
                    results.append(AVresult)

    create_log(log_type="scan_result", log_detail="standard_scan", subject_name=request.username, subject_id=user_id, db=db, scan_result=results)

    return {"results": results}

@api.post("/urlscans/heavyscans")
async def scanurl_heavy(request: URLRequestHeavy, APIKey=Security(APIKeyHeader(name="X-API-KEY")),db: Session = Depends(get_db)):
    authenticate_user(request=request, db=db, APIKey=APIKey)

    user_id = search_user_id(db=db, target_username=request.username)
    assert user_id is not None

    async with httpx.AsyncClient() as httpxclient:
        AVresult = await AVscan(scantype="url_heavy", target=request.target_url, id_detail=request.url_id, httpxclient=httpxclient)

    create_log(log_type="scan_result", log_detail="standard_scan", subject_name=request.username, subject_id=user_id, db=db, scan_result=AVresult)

    return {"results": AVresult}

@api.post("/domainscans")
async def scan_domain(request: DomainRequest, APIKey=Security(APIKeyHeader(name="X-API-KEY")),db: Session = Depends(get_db)):
    authenticate_user(request=request, db=db, APIKey=APIKey)

    user_id = search_user_id(db=db, target_username=request.username)
    assert user_id is not None

    results = []
    async with httpx.AsyncClient() as httpxclient:
        for option in request.scan_engines:
            match option:
                case "alienvault":
                    AVresult = await AVscan(scantype="domain", target=request.target_domain, id_detail=request.domain_id, httpxclient=httpxclient)
                    results.append(AVresult)
                case "virustotal":
                    VTresult = await VTscan(scantype="domain", target=request.target_domain, id_detail=request.domain_id, httpxclient=httpxclient)
                    results.append(VTresult)

    create_log(log_type="scan_result", log_detail="standard_scan", subject_name=request.username, subject_id=user_id, db=db, scan_result=results)

    return {"results": results}
            



                
                    


    
