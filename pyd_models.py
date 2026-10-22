from pydantic import BaseModel, field_validator, Field
from ipaddress import IPv4Address, IPv6Address
from fastapi import HTTPException
class IPRequest(BaseModel):
    name: str
    scan_type: str = "custom"
    target_ip: IPv4Address | IPv6Address
    key: str
    ip_id: str = "Not Specified"
    #The option1 attribute is used when a scan using a specific service is requried, its a list of the options
    scan_engine : list = []
    #The report_age attribute is used with abuselpdb for selecting the age of IP reports
    report_age : int = 0
    @field_validator("scan_type")
    @classmethod
    def check_scantype(cls, value:list[str]):
        options = ["recon_ip_scan", "own_ip", "scan_ip", "custom"]
        if value not in options:
            raise HTTPException(
                status_code=422,
                detail="The selected scan type doesnt exist or is invalid"
            )
        return value
    
    @field_validator("scan_engine")
    @classmethod
    def check_option1(cls, value:list[str]):
        #Valid options will be placed here
        corrected_options = []
        #If a user wants to just use ipinfo they shoudl do a "recon_ip_scan" scan type
        options = ["abuselpdb", "virustotal", "alienvault"]
        for element in value:
            if element in corrected_options:
                continue

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
    def scantype_check(cls, value:list[str]):
        corrected_options = []
        options = ["virustotal", "alienvault"]
        for option in value:
            #This conditional ensures that an engine is not used twice
            if option in corrected_options:
                continue
            
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
    def check_scan_engine(cls, value:list[str]):
        corrected_options = []
        aval_option = ["virustotal", "alienvault"]
        for element in value:
            if element in corrected_options:
                continue
            
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
    def check_scan_engine(cls, value: list[str]):
        aval_option = ["alienvault", "virustotal"]
        corrected_options = []
        for element in value:
            if element in corrected_options:
                continue
            
            if element in aval_option:
                corrected_options.append(element)
        
        if not corrected_options:
            raise HTTPException(
                        status_code=422,
                        detail="No valid engine was specified in the request"
                    )
        
        return corrected_options
