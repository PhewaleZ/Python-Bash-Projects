import requests
import os
from dotenv import load_dotenv
from time import sleep
from ipaddress import IPv4Address, IPv6Address
from typing import Literal
import json
#This function is what makes the HTTP request and validates it and returns if it is the expected response or an error
def send_request(url: str, headers: dict, payload={}, is_url=False) -> tuple[ bool, str | requests.Response]:
    last_error = "Unknown"
    for _ in range(4):
        try:
            if is_url is True:
                response = requests.post(
                    url=url, headers=headers, timeout=20, data=payload
                )

            else:
                response = requests.get(
                    url=url, headers=headers, timeout=20
                )

            response.raise_for_status()

        except requests.exceptions.Timeout:
            return (False, "Could not communicate with the VirusTotal API server, TIMEOUT occured.")

        except requests.exceptions.ConnectionError:
            return (False, "Could not connect to the VT API server.")

        #NOTE:In this match case block, the first 3 cases are errors that if occur, there is no point in sending another http request
        except requests.exceptions.HTTPError as e:
            if e.response is None:
                return (False, str(e))
            match e.response.status_code:
                case 403:
                    return (False, "Access denied by Virus total server")
                case 429:
                    return (False, "The rate limit for the VT API server has been reached")
                case 400 | 401 | 404:
                    return (False, f"The following error has occured with the VT API query: {str(e)} ")
                case _:
                    last_error = f"HTTP {e.response.status_code}: {e.response.reason}"
                    continue

        except requests.exceptions.RequestException as e:
            assert e.response is not None
            last_error = f"HTTP code: {e.response.status_code}: {e.response.reason}"
            continue

        else:
            return (True, response)
        
    #If the for loop reaches all 4 iterations and a "non-critical" error has not occured but an error none the less, then the last error is returned along with a bool indicating that an error has occured
    return (False, last_error)
    
#NOTE: The scanning ip address VT endpoint accepts both ipv6 and ipv4 addresses
#The variable scan_type will indicate whether an IP ao domain is being scanned
def scan_ip_domain_vt(target_ip_domain: IPv4Address | IPv6Address| str, scan_type: Literal["DOMAIN", "IP"]) -> tuple[bool, str | dict]:
    load_dotenv()
    url= ''
    API_KEY = os.getenv("VIRUSTOTALAPI_KEY")

    if API_KEY == None:
        return (False,'Virus Total API key is None')

    if scan_type == 'IP':           
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{target_ip_domain}"
    
    if scan_type == 'DOMAIN':
        url = f"https://www.virustotal.com/api/v3/domains/{target_ip_domain}"

    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY
    }

    request_check = send_request(url=url, headers=headers)

    if request_check[0] is True:
        assert not isinstance(request_check[1], str)
        virus_total_res = aggregate_vt_results_ip_domain(rec_response=request_check[1], target_name=target_ip_domain) 
        return (True, virus_total_res)
    else:
        return (False, request_check[1]) # pyright: ignore[reportReturnType]

def aggregate_vt_results_ip_domain(rec_response: requests.Response, target_name: IPv4Address|IPv6Address|str) -> dict:
    warning: list[str] = []

    json_rec_response = rec_response.json()
    last_analysis_stats = json_rec_response["data"]["attributes"]["last_analysis_stats"]

    malicious_count=(last_analysis_stats["malicious"])
    suspicious_count=(last_analysis_stats["suspicious"])
    undetected_count=(last_analysis_stats["undetected"])
    harmless_count=(last_analysis_stats["harmless"])
    timeout_count=(last_analysis_stats["timeout"])
    total_engines =(malicious_count+suspicious_count+undetected_count+harmless_count+timeout_count)
    lvl3_ratio = round(undetected_count/total_engines, ndigits=2)
    lvl2_ratio = round(harmless_count/total_engines, ndigits=2)
    lvl1_ratio = round((malicious_count+suspicious_count)/total_engines, ndigits=2)
    if (timeout_count > (0.35 * total_engines)):
        warning.append("Large number of engines queried by VT's API failed to scan")

    formatted_response = {
        'target': str(target_name),
        'warnings': warning,
        'details':{
            "level3":{
                "count":undetected_count,
                "ratio":lvl3_ratio
            },
            "level2":{
                "count":harmless_count,
                "ratio":lvl2_ratio
            },
            "level1":{
                "count":malicious_count+suspicious_count,
                "ratio":lvl1_ratio
            }
        }
    }
    
    return (formatted_response)


def scan_file_vt(file_hash: str, target_file_name:str) -> tuple[bool, str|dict]:
    load_dotenv()

    API_KEY = os.getenv("VIRUSTOTALAPI_KEY")

    if API_KEY == None:
        return (False, 'VirusTotal API key is None')
    
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

    headers = {
        "x-apikey": API_KEY,
        "accept": "application/json"
    }

    request_check = send_request(url=url, headers=headers)

    #NOTE:if the first index is true, then a response.Request was returned, not a string
    if request_check[0] is True:
        assert not isinstance(request_check[1], str)
        virus_total_res = aggregate_vt_results_filehash(rec_response=request_check[1], target_name=target_file_name)
        return(True, virus_total_res) 
    else:
        return (False, request_check[1])  # pyright: ignore[reportReturnType]


def aggregate_vt_results_filehash(rec_response: requests.Response,target_name: str) -> dict:
    warning: list[str] = []
    
    json_rec_response = rec_response.json()
    sigma_stats= json_rec_response["data"]["attributes"]["sigma_analysis_stats"]
    last_analysis_stats= json_rec_response["data"]["attributes"]["last_analysis_stats"]

    sigma_stats_critical= sigma_stats["critical"]
    sigma_stats_high= sigma_stats["high"]
    sigma_stats_medium= sigma_stats["medium"]
    sigma_stats_low= sigma_stats["low"]
    total_sigma_stats= sigma_stats_critical+sigma_stats_high+sigma_stats_medium+sigma_stats_low
    if sigma_stats_critical > 0 or (sigma_stats_high+sigma_stats_medium) > total_sigma_stats*0.4:
        warning.append("Strange or abnormal patterns observed in 'sigma statistics'")

    harmless_vote_count= json_rec_response["data"]["attributes"]["total_votes"]["harmless"]
    malicious_vote_count= json_rec_response["data"]["attributes"]["total_votes"]["malicious"]
    total_vote_engines = harmless_vote_count+malicious_vote_count
    malicious_vote_ratio = round(malicious_vote_count/total_vote_engines, ndigits=2)
    match malicious_vote_ratio:
        case x if 1 < x <= 0.7:
            vote_verdict = 'HARMFUL'
        case x if 0.7 < x <= 0.5:
            vote_verdict = 'CONCERNING'
        case x if 0.5 < x <= 0.2:
            vote_verdict = 'OKAY'
        case _:
            vote_verdict = 'SAFE'

    malicious_count=last_analysis_stats["malicious"]
    suspicious_count=last_analysis_stats["suspicious"]
    undetected_count=last_analysis_stats["undetected"]
    harmless_count=last_analysis_stats["harmless"]
    timeout_count=last_analysis_stats["timeout"]
    conf_timeout=last_analysis_stats["confirmed-timeout"]
    failure_count=last_analysis_stats["failure"]
    type_unsupported_count=last_analysis_stats["type-unsupported"]
    total_engines= malicious_count+suspicious_count+undetected_count+harmless_count+timeout_count+conf_timeout+failure_count+type_unsupported_count
    lvl3_ratio=round((undetected_count)/total_engines, ndigits=2)
    lvl2_ratio=round((harmless_count+(int(harmless_vote_count*0.003)))/total_engines, ndigits=2)
    lvl1_ratio=round((malicious_count+suspicious_count+(int(malicious_vote_count*0.003)))/total_engines, ndigits=2)
    if ((timeout_count+conf_timeout+failure_count+type_unsupported_count)/total_engines) > 0.35:
        warning.append("Large number of engines queried by VT's API failed to scan")

    formatted_response={
        "target_file":target_name,
        "warnings": warning,
        "details":{
            "community_vote":{
                "vote_verdict": vote_verdict,
                "malicious_ratio": malicious_vote_ratio
            },
            "level3":{
                "count":undetected_count,
                "ratio":lvl3_ratio
            },
            "level2":{
                "count":harmless_count+(int(harmless_vote_count*0.003)),
                "ratio":lvl2_ratio
            },
            "level1":{
                "count":malicious_count+suspicious_count+(int(malicious_vote_count*0.003)),
                "ratio":lvl1_ratio
            }
        }
    }

    return formatted_response

def scan_url_vt(target_url: str):
    load_dotenv()

    API_KEY = os.getenv("VIRUSTOTALAPI_KEY")

    if API_KEY == None:
        return (False, 'Virus Total API key is None')
    
    url = "https://www.virustotal.com/api/v3/urls"

    payload = { "url": target_url }
    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY,
        "content-type": "application/x-www-form-urlencoded"
    }

    request_check = send_request(url=url, headers=headers, is_url=True, payload=payload)

    #NOTE:if the first index is true, then a response.Request was returned, not a string
    if request_check[0] is False:
        return (False, f"The request could not be made to Virustotal's API server, LAST KNOWN STATUS IS:{request_check[1]}")
    
    else:
        assert not isinstance(request_check[1], str)
        ret_result_id = request_check[1].json()
        analysis_id = ret_result_id["data"]["id"]

    last_status = ''
    #This is the part which attempts to retrieve the analysis
    for _ in range(10):
        url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

        headers = {
            "accept": "application/json",
            "x-apikey": API_KEY
        }
        #The request_check tuple is overwritten in this new request
        request_check = send_request(url=url, headers=headers, is_url=False)
        if request_check[0] is False:
            last_status = request_check[1]
            sleep(8)
            continue
        else:
            assert not isinstance(request_check[1], str)
            response = request_check[1].json() 

        status = (
            response.get("data", {}).get("attributes", {}).get("status")
        )
        if status == 'queued' or status == 'running':
            last_status = status
            sleep(8)
            continue
        else:
            virus_total_res = aggregate_vt_results_urlscan(rec_response=response, target_name=target_url)
            return (True, virus_total_res)
    
    return (False, f'The api took too long do return a finished response, LAST KNOWN STATUS IS {last_status}')
    
#info1 stores the url which was scanned
def aggregate_vt_results_urlscan(rec_response: requests.Response, target_name: str) -> dict:
    warning: list[str] = []
    json_rec_response = rec_response.json()
    stats = json_rec_response["data"]["attributes"]["stats"]

    malicious_count=stats["malicious"]
    suspicious_count=stats["suspicious"]
    undetected_count=stats["undetected"]
    harmless_count=stats["harmless"]
    timeout_count=stats["timeout"]
    conf_timeout=stats["confirmed_timeout"]
    failure_count=stats["failure"]
    type_unsupported_count=stats["type_unsupported"]
    total_engines = malicious_count+suspicious_count+undetected_count+harmless_count+timeout_count+conf_timeout+failure_count+type_unsupported_count
    lvl3_ratio = round(undetected_count/total_engines, ndigits=2)
    lvl2_ratio = round(harmless_count/total_engines, ndigits=2)
    lvl1_ratio = (malicious_count+suspicious_count)/total_engines

    if ((timeout_count+conf_timeout+failure_count+type_unsupported_count)/total_engines) > 0.35:
        warning.append("Large number of engines queried by VT's API failed to scan")
    formatted_response={
        "target_url":target_name,
        "warnings": warning,
        "details":{
            "level3":{
                "count":undetected_count,
                "ratio":lvl3_ratio
            },
            "level2":{
                "count":harmless_count,
                "ratio":lvl2_ratio
            },
            "level1":{
                "count":malicious_count+suspicious_count,
                "ratio":lvl1_ratio
            }
        }
    }
    return formatted_response
