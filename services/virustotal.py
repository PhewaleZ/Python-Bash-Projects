import requests
import os
from dotenv import load_dotenv
from time import sleep
from ipaddress import IPv4Address, IPv6Address
from typing import Literal
#NOTE: When a scan is done by virustotal and one of the scanning functions are used, take note that a tuple is returned, the first value in the tuple is going to be a boolean to indicate whether the result was successful
class PermenantERROR(Exception):
    pass
class NONPermenantERROR(Exception):
    pass

#This function is what makes the HTTP request and validates it and returns if it is the intended response or an error
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
            return (False, "Couldn't communicate with the VirusTotal server, TIMEOUT occured.")

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
            last_error = f"HTTP code: {e.response.status_code}: {e.response.reason}" #type: ignore as this error will never occur in normal circumstances
            continue

        else:
            return (True, response)
        
    #If the for loop reaches all 4 iterations and a "non-critical" error has not occured but an error none the less, then the last error is returned along with a bool indicating that an error has occured
    return (False, last_error)
    
#NOTE: The scanning ip address VT endpoint accepts both ipv6 and ipv4 addresses
#The variable scan_type will indicate whether an IP ao domain is being scanned
def scan_IP_DOMAIN_VT(target_IP_DOMAIN: IPv4Address | IPv6Address| str, scan_type: Literal["DOMAIN", "IP"]) -> tuple[bool, str | dict]:
    load_dotenv()
    api_key = os.getenv("VIRUSTOTALAPI_KEY")

    if api_key == None:
        return (False,'Virus Total API key is None')

    if scan_type == 'IP': 
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{target_IP_DOMAIN}"
    
    if scan_type == 'DOMAIN':
        url = f"https://www.virustotal.com/api/v3/domains/{target_IP_DOMAIN}"

    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    check = send_request(url=url, headers=headers) #type: ignore the unbound issue will never happen as the scan type will always be "IP" or "DOMAIN" 

    if check[0] is True:
        virus_total_res = aggregate_virustotal_results_IP_and_DOMAIN(rec_response=check[1], target_name=target_IP_DOMAIN)
        return (True, virus_total_res)
    else:
        return (False, check[1]) #type: ignore

#info1 contains the IP address of the target IP address or Domain name
def aggregate_virustotal_results_IP_and_DOMAIN(rec_response, target_name: IPv4Address|IPv6Address|str) -> dict:
    warning = []

    rec_response = rec_response.json()
    malicious_count=rec_response["data"]["attributes"]["last_analysis_stats"]["malicious"]
    suspicious_count=rec_response["data"]["attributes"]["last_analysis_stats"]["suspicious"]
    undetected_count=rec_response["data"]["attributes"]["last_analysis_stats"]["undetected"]
    harmless_count=rec_response["data"]["attributes"]["last_analysis_stats"]["harmless"]
    timeout_count=rec_response["data"]["attributes"]["last_analysis_stats"]["timeout"]
    total_engines =malicious_count+suspicious_count+undetected_count+harmless_count+timeout_count
    lvl2_ratio = harmless_count/total_engines
    lvl3_ratio = (malicious_count+suspicious_count)/total_engines
    if (timeout_count > (0.35 * total_engines)):
        warning.append("Large number of engines queried by VT's API failed to scan")

    formatted_response = {
        'target': target_name,
        'country': rec_response["data"]["attributes"]["country"],
        'warnings': warning,
        'details':{
            "level3":{
                "count":undetected_count,
                "ratio":undetected_count/total_engines
            },
            "level2":{
                "count":harmless_count,
                "ratio":lvl2_ratio
            },
            "level1":{
                "count":malicious_count+suspicious_count,
                "ratio":lvl3_ratio
            }
        }
    }
    
    #NOTE: ADD FUNCTION WHICH PUTS THE DATA INTO THE DATABASE HERE
    return (formatted_response)


#It is assumed that the the file will be converted into an sha-256 hash before reaching this file
def scan_file_VT(file_hash, target_file_name) -> tuple[bool, str|dict]:
    load_dotenv()

    api_key = os.getenv("VIRUSTOTALAPI_KEY")

    if api_key == None:
        return (False, 'Virus Total API key is None')
    
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

    headers = {
        "x-apikey": api_key,
        "accept": "application/json"
    }

    check = send_request(url=url, headers=headers)
    #If the first index is true then it means the request was successful and the intended response was received
    #If the first index is false then an error has occured so the second index is te error messaage
    if check[0] is True:
        virus_total_res = aggregate_virustotal_results_FILEHASH(rec_response=check[1], target_name=target_file_name)
        return (True, virus_total_res)
    else:
        return (False, check[1]) #type: ignore


def aggregate_virustotal_results_FILEHASH(rec_response,target_name: str) -> dict:
    warning = []
    rec_response = rec_response.json()

    sigma_stats=rec_response["data"]["attributes"]["sigma_analysis_stats"]
    sigma_stats_critical=sigma_stats["critical"]
    sigma_stats_high=sigma_stats["high"]
    sigma_stats_medium=sigma_stats["medium"]
    sigma_stats_low=sigma_stats["low"]
    total_sigma_stats=sigma_stats_critical+sigma_stats_high+sigma_stats_medium+sigma_stats_low
    if sigma_stats_critical > 0 or (sigma_stats_high+sigma_stats_medium) > total_sigma_stats*0.4:
        warning.append("Strange or abnormal patterns observed")

    harmless_vote_count= rec_response["data"]["attributes"]["total_votes"]["harmless"]
    malicious_vote_count= rec_response["data"]["attributes"]["total_votes"]["malicious"]
    total_vote_engines = harmless_vote_count+malicious_vote_count
    malicious_vote_ratio = (malicious_vote_count/total_vote_engines)
    match malicious_vote_ratio:
        case x if 1 < x <= 0.7:
            vote_verdict = 'HARMFUL'
        case x if 0.7 < x <= 0.5:
            vote_verdict = 'CONCERNING'
        case x if 0.5 < x <= 0.2:
            vote_verdict = 'OKAY'
        case _:
            vote_verdict = 'SAFE'

    malicious_count=rec_response["data"]["attributes"]["stats"]["malicious"]
    suspicious_count=rec_response["data"]["attributes"]["stats"]["suspicious"]
    undetected_count=rec_response["data"]["attributes"]["stats"]["undetected"]
    harmless_count=rec_response["data"]["attributes"]["stats"]["harmless"]
    timeout_count=rec_response["data"]["attributes"]["stats"]["timeout"]
    conf_timeout=rec_response["data"]["attributes"]["stats"]["confirmed_timeout"]
    failure_count=rec_response["data"]["attributes"]["stats"]["failure"]
    type_unsupported_count=rec_response["data"]["attributes"]["stats"]["type_unsupported"]
    total_engines= malicious_count+suspicious_count+undetected_count+harmless_count+timeout_count+conf_timeout+failure_count+type_unsupported_count
    lvl2_ratio=round((harmless_count+(int(harmless_vote_count*0.003)))/total_engines)
    lvl3_ratio=round((malicious_count+suspicious_count+(int(malicious_vote_count*0.003)))/total_engines)
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
                "ratio":round((undetected_count)/total_engines, ndigits=2)
            },
            #The usage of "int" will remove whatever comes after the decimal point
            "level2":{
                "count":harmless_count+(int(harmless_vote_count*0.003)),
                "ratio":lvl2_ratio
            },
            "level1":{
                "count":malicious_count+suspicious_count+(int(malicious_vote_count*0.003)),
                "ratio":lvl3_ratio
            }
        }
    }

    return formatted_response

#THIS SIMPLY RETURNS AN ANALYSIS ID, ANOTHER FUNCTION WILL FETCH THE DATA
def scan_URL_VT(target_URL):
    load_dotenv()

    api_key = os.getenv("VIRUSTOTALAPI_KEY")

    if api_key == None:
        return (False, 'Virus Total API key is None')
    
    url = "https://www.virustotal.com/api/v3/urls"

    payload = { "url": target_URL }
    headers = {
        "accept": "application/json",
        "x-apikey": api_key,
        "content-type": "application/x-www-form-urlencoded"
    }

    check = send_request(url=url, headers=headers, is_url=True, payload=payload)

    #This is what will occur if the query fails and nothing else is done
    if check[0] is False:
        return (False, check[1])
    else:
        response_json = (response.json()) #type: ignore 
        analysis_id = response["data"]["id"] #type: ignore

    last_status = ''
    #This is the part which attempts to retrieve the analysis
    for _ in range(10):
        url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

        headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }

        check = send_request(url=url, headers=headers, is_url=False)
        if check[0] is False:
            last_status = check[1]
            sleep(8)
            continue
        else:
            response = check[1].json() #type: ignore

        status = (
            response.get("data", {}).get("attributes", {}).get("status")
        )
        if status == 'queued' or status == 'running':
            last_status = status
            sleep(8)
            continue
        else:
            virus_total_res = aggregate_virustotal_results_URLSCAN(rec_response=response, target_name=target_URL)
            return (True, virus_total_res)
    
    return (False, f'The api took too long do return a finished response, LAST KNOWN STATUS IS {last_status}')
    
#info1 stores the url which was scanned
def aggregate_virustotal_results_URLSCAN(rec_response, target_name: str) -> dict:
    rec_response = rec_response.json()
    warning = []

    malicious_count=rec_response["data"]["attributes"]["stats"]["malicious"]
    suspicious_count=rec_response["data"]["attributes"]["stats"]["suspicious"]
    undetected_count=rec_response["data"]["attributes"]["stats"]["undetected"]
    harmless_count=rec_response["data"]["attributes"]["stats"]["harmless"]
    timeout_count=rec_response["data"]["attributes"]["stats"]["timeout"]
    conf_timeout=rec_response["data"]["attributes"]["stats"]["confirmed_timeout"]
    failure_count=rec_response["data"]["attributes"]["stats"]["failure"]
    type_unsupported_count=rec_response["data"]["attributes"]["stats"]["type_unsupported"]
    total_engines = malicious_count+suspicious_count+undetected_count+harmless_count+timeout_count+conf_timeout+failure_count+type_unsupported_count
    lvl2_ratio = harmless_count/total_engines
    lvl3_ratio = (malicious_count+suspicious_count)/total_engines

    if ((timeout_count+conf_timeout+failure_count+type_unsupported_count)/total_engines) > 0.35:
        warning.append("Large number of engines queried by VT's API failed to scan")
    formatted_response={
        "target_url":target_name,
        "warnings": warning,
        "details":{
            "level3":{
                "count":undetected_count,
                "ratio":undetected_count/total_engines
            },
            "level2":{
                "count":harmless_count,
                "ratio":lvl2_ratio
            },
            "level1":{
                "count":malicious_count+suspicious_count,
                "ratio":lvl3_ratio
            }
        }
    }
    return formatted_response
