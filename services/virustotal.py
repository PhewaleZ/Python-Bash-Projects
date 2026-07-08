import requests
import os
from dotenv import load_dotenv
from time import sleep

#NOTE: When a scan is done by virustotal and one of the scanning functions are used, take note that a tuple is returned, the first value in the tuple is going to be a boolean to indicate whether the result was successful
class PermenantERROR(Exception):
    pass
class NONPermenantERROR(Exception):
    pass

#This function is the 'brain' of error checking
#By default the payload is an empty string, if the endpoint needs to be the url endpoint then the payload parameter is set right before the function is called
#The value is_url will determine whether the conduct POST or GET request, in other words whether or not a url is being scanned
#This function is what returns the python formatted json response
def response_analysis(url, headers, payload: dict,is_url=False):
    #NOTE: This part involves the request to virustotal being done over and over again if an error occurs
    #NOTE: confirmation[0] indicates whether or not the received response is okay
    #NOTE: confirmation[1] indicates the type/severity of the error, if critcal then the request is not repeated
    #NOTE: confirmation[2] provides more detail on the error
    okay = False
    count = 1
    while count <= 5:

        if is_url is False:
            try:
                response = requests.get(url=url, headers=headers, timeout=60)
            except requests.exceptions.Timeout:
                return (False, "Couldnt communicate with Virustotal server")
        else:
            try:
                response = requests.post(url=url, headers=headers, timeout=60,data=payload)
            except requests.exceptions.Timeout:
                return (False, "Couldnt communicate with Virustotal server")
            
        confirmation = response_error_check(rec_response=response)

        if confirmation[0] is False and confirmation[1] == 'NON-CRITICAL':
            count +=1
            last_error=confirmation[2]
            continue

        if confirmation[0] is False and confirmation[1] == 'CRITICAL':
            #This will eject out of this and starts the process of returning an error to the user
            return (False, confirmation[2])
        
        if confirmation[0] is True:
            okay = True
            break

    if okay is False:
        return (False, last_error)
    
    if okay is True:
        return (True, response)

#This function is to check for any errors in the result recieved by API
def response_error_check(rec_response):
    error = None
    json_rec_response=rec_response.json()
    try:
        if "error" in json_rec_response:
             err_code = json_rec_response["error"]["code"]

             match err_code:
                 case "QuotaExceededError":
                    error="The limit of how many scans on Virus total has been reached"
                    raise PermenantERROR
                 case "AuthenticationRequiredError":
                    error="The api key has a problem"
                    raise PermenantERROR
                 case "BadRequestError":
                    error="The request sent may be wrong"
                    raise PermenantERROR
                 case "TransientError":
                    raise NONPermenantERROR
         
        if rec_response.status_code != 200:
            raise NONPermenantERROR
            
    except PermenantERROR:
        return (False, 'CRITICAL', error)
    except NONPermenantERROR:
        sleep(4)
        error="Too many failed attempts"
        return (False, 'NON-CRITICAL', error)
    else:
        return (True,'',error)
    

#The variable scan_type will indicate whether an IP ao domain is being scanned
async def scan_IP_DOMAIN_VT(target_IP_DOMAIN, scan_type):
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

    #NOTE: check[1] can return the successful results if check[0] is true else if check[0] is false then check[1] is the last error message
    #The returned response in the tuple "check", if succssful, is a python formatted json
    check = response_analysis(url=url, headers=headers)
    if check[0] is True:
        virus_total_res = aggregate_virustotal_results_IP_and_DOMAIN(rec_response=check[1], info1=target_IP_DOMAIN)
        return (True, virus_total_res)
    
    if check[1] is False:
        return (False, check[1])

#info1 contains the IP address of the target IP address or Domain name
def aggregate_virustotal_results_IP_and_DOMAIN(rec_response, info1):
    warning = []

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
        'target': info1,
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



async def scan_file_VT(file_hash):
    load_dotenv()

    api_key = os.getenv("VIRUSTOTALAPI_KEY")

    if api_key == None:
        return (False, 'Virus Total API key is None')
    
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

    headers = {
        "x-apikey": api_key,
        "accept": "application/json"
    }

    check = response_analysis(url=url, headers=headers)
    if check[0] is True:
        virus_total_res = aggregate_virustotal_results_FILEHASH(rec_response=check[1])
        return (True, virus_total_res)
    
    if check[1] is False:
        return (False, check[1])


def aggregate_virustotal_results_FILEHASH(rec_response,info1):
    warning = []

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
        "target_url":info1,
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

    check = response_analysis(url=url, headers=headers, is_url=True, payload=payload)

    #This is what will occur if the query fails and nothing else is done
    if check[0] is False:
        return (False, check[1])
    #If the query was done properly and was successful then the code continues
        
    analysis_id = check[1]["data"]["id"]
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

    headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }
    
    count = 1
    while count <= 15:
        url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

        headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }

        response = requests.get(url, headers=headers)
        response = response.json()

        status = (
            response.get("data", {}).get("attributes", {}).get("status")
        )
        if status == 'queued' or status == 'running':
            sleep(5)
            count += 1
            continue
        else:
            virus_total_res = aggregate_virustotal_results_URLSCAN(rec_resonse=response, info1=target_URL)
            return (True, virus_total_res)
    
    return (False, f'The api took too long do return a finished response, LAST KNOWN STATUS IS {response["data"]["attributes"]["status"]}')
    
#info1 stores the url which was scanned
def aggregate_virustotal_results_URLSCAN(rec_response, info1):
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
        "target_url":info1,
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
