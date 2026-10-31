from pydantic import BaseModel, field_validator, Field
from ipaddress import IPv4Address, IPv6Address
from fastapi import HTTPException
class IPRequest(BaseModel):
    username: str
    scan_type: str = "custom"
    target_ip: IPv4Address | IPv6Address
    key: str
    ip_id: str = "Not Specified"
    scan_engines : list[str] = []
    report_age : int = 0
    @field_validator("scan_type")
    @classmethod
    def check_scantype(cls, scan_type:str):
        aval_scan_options = ["recon_ip_scan", "own_ip", "scan_ip", "custom"]
        if scan_type not in aval_scan_options:
            raise HTTPException(
                status_code=422,
                detail="The selected scan type doesnt exist or is invalid"
            )
        return scan_type
    
    @field_validator("scan_engines")
    @classmethod
    def check_option1(cls, scan_engines:list[str]):
        corrected_scan_engines = []
        aval_scan_options = ["abuselpdb", "virustotal", "alienvault"]
        for option in scan_engines:
            #NOTE: This prevents the same scan engine being used over and over just because the user input it more than twice
            if option in corrected_scan_engines:
                continue

            if option in aval_scan_options:
                corrected_scan_engines.append(option)

        if not corrected_scan_engines:
            raise HTTPException(
                    status_code=422,
                    detail="No valid engine was specified in the request"
                        )
        else:
            return corrected_scan_engines

class FileRequest(BaseModel):
    username: str
    target_hash: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    key: str
    file_id:str = "Not Specified"
    scan_engines: list[str]
    @field_validator("scan_engines")
    @classmethod
    def scantype_check(cls, scan_engines:list[str]):
        corrected_scan_engines = []
        aval_scan_options = ["virustotal", "alienvault"]
        for option in scan_engines:
            if option in corrected_scan_engines:
                continue
            
            if option in aval_scan_options:
                corrected_scan_engines.append(option)

        if not corrected_scan_engines:
            raise HTTPException(
                status_code=422,
                detail="No valid engine was specified in the request"
            )
        
        return corrected_scan_engines

class URLRequestLight(BaseModel):
    username: str
    key: str
    url_id: str="Not Specified"
    target_url: str
    scan_engines: list[str]
    @field_validator("scan_engines")
    @classmethod
    def check_scan_engine(cls, scan_engines:list[str]):
        corrected_scan_engines = []
        aval_scan_options = ["virustotal", "alienvault"]
        for element in scan_engines:
            if element in corrected_scan_engines:
                continue
            
            if element in aval_scan_options:
                corrected_scan_engines.append(element)

        if not corrected_scan_engines:
            raise HTTPException(
                status_code=422,
                detail="No valid engine was specified in the request"
            )

        return corrected_scan_engines

class URLRequestHeavy(BaseModel):
    username: str
    key: str
    url_id: str="Not Specified"
    target_url: str

class DomainRequest(BaseModel):
    username: str
    key: str
    domain_id: str="Not Specified"
    target_domain: str
    scan_engines: list[str]
    @field_validator("scan_engines")
    @classmethod
    def check_scan_engine(cls, scan_engines: list[str]):
        aval_scan_options = ["alienvault", "virustotal"]
        corrected_options = []
        for option in scan_engines:
            if option in corrected_options:
                continue
            
            if option in aval_scan_options:
                corrected_options.append(option)
        
        if not corrected_options:
            raise HTTPException(
                        status_code=422,
                        detail="No valid engine was specified in the request"
                    )
        
        return corrected_options
