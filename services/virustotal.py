import requests
import os
from dotenv import load_dotenv
import time

#NOTE: When a scan is done by virustotal and one of the scanning functions are used, take note that a tuple is returned, the first value in the tuple is going to be a boolean to indicate whether the result was successful
class PermenantERROR(Exception):
    pass
class NONPermenantERROR(Exception):
    pass

#This function is the 'brain' of error checking
def response_analysis(url, headers):
    #NOTE: This part involves the request to virustotal being done over and over again if an error occurs
    #NOTE: confirmation[0] indicates whether or not the received response is okay
    #NOTE: confirmation[1] indicates the type/severity of the error, if critcal then the request is not repeated
    #NOTE: confirmation[2] provides more detail on the error
    okay = False
    count = 1
    while count <= 3:
        response = requests.get(url=url, headers=headers)
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
        return (True, response.json())

#This function is to check for any errors in the result recieved by API
def response_error_check(rec_response):
    json_rec_response=rec_response.json()
    error = None
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
         
        if rec_response.status_code in [500, 502, 503, 504, 507, 505]:
            raise NONPermenantERROR
            
    except PermenantERROR:
        return (False, 'CRITICAL', error)
    except NONPermenantERROR:
        time.sleep(4)
        error="Too many failed attempts"
        return (False, 'NON-CRITICAL', error)
    else:
        return (True,'',error)
    

#The variable scan_type will indicate whether an IP ao domain is being scanned
async def scan_IP_DOMAIN(target_IP_DOMAIN, scan_type):
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
    #this calculates the total number of engines whihc virustotal queried
    total_engines = rec_response["data"]["attributes"]["last_analysis_stats"]["malicious"]+rec_response["data"]["attributes"]["last_analysis_stats"]["suspicious"]+rec_response["data"]["attributes"]["last_analysis_stats"]["undetected"]+rec_response["data"]["attributes"]["last_analysis_stats"]["harmless"]+rec_response["data"]["attributes"]["last_analysis_stats"]["timeout"]
    warning= False
    #NOTE: HERE WORK ON ADDING A FEATURE TO INFORM OF ABNORMAL RESULTS SUCH AS A LARGE NUMBER OF TIMEOUTS
    if (rec_response["data"]["attributes"]["last_analysis_stats"]["timeout"] > (0.35 * total_engines)):
        warning = True

    formatted_response = {
        'target IP': info1,
        'country': rec_response["data"]["attributes"]["country"],
        'warning': warning,
        'details':{
            "level2":rec_response["data"]["attributes"]["last_analysis_stats"]["harmless"]+rec_response["data"]["attributes"]["last_analysis_stats"]["undetected"],
            "level1":rec_response["data"]["attributes"]["last_analysis_stats"]['suspicious'] +rec_response["data"]["attributes"]["last_analysis_stats"]["malicious"] # type: ignore
        } # type: ignore
    }
    
    #NOTE: ADD FUNCTION WHICH PUTS THE DATA INTO THE DATABASE HERE
    return (formatted_response)



async def scan_file(file_hash):
    load_dotenv()

    api_key = os.getenv("VIRUSTOTALAPI_KEY")

    if api_key == None:
        return (False, 'Virus Total API key is None')
    
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

    headers = {
        "x-apikey": api_key,
        "accept": "application/json"
    }

    okay = False
    #NOTE: This part involves the request to virustotal being done over and over again if an error occurs
    #NOTE: confirmation[0] indicates whether or not the received response is okay
    #NOTE: confirmation[1] indicates the type/severity of the error, if critcal then the request is not repeated
    #NOTE: confirmation[2] provides more detail on the error
    while count <= 3:
        response = requests.get(url, headers=headers, timeout=10)
        confirmation = response_error_check(rec_response=response)
        if confirmation[0] == False and confirmation[1] == 'NON-CRITICAL':
            count +=1
            last_error=confirmation[2]

        if confirmation[0] == False and confirmation[1] == 'CRITICAL':
            #This will eject out of this and starts the process of returning an error to the user
            return (False, confirmation[2])
        
        if confirmation[0] == True:
            okay = True
    #This part also catches an error
    if okay == False:
        return (False, last_error)
     
    
    #If no errors are caught then the results are aggregated
    virus_total_res = aggregate_virustotal_results_FILEHASH(response=response)
    return (True, virus_total_res)


def aggregate_virustotal_results_FILEHASH(response):
    harmless_count= response["data"]["attributes"]["total_votes"]["harmless"]
    malicious_count= response["data"]["attributes"]["total_votes"]["malicious"]
    total_engines = harmless_count+malicious_count
    malicious_ratio = (malicious_count/total_engines)
    value = round(malicious_ratio, 2)
    match malicious_ratio:
        case x if 1 < x <= 0.7:
            verdict = 'HARMFUL'
        case x if 0.7 < x <= 0.5:
            verdict = 'CONCERNING'
        case x if 0.5 < x <= 0.2:
            verdict = 'OKAY'
        case _:
            verdict = 'SAFE'

    formatted_response ={
        'hash':response["data"]["attributes"]["sha256"],
        'details':{
            'verdict': verdict,
            'actual_value': value,
        }
    }

    #NOTE: Add function which inputs to database here

    return formatted_response

#THIS SIMPLY RETURNS AN ANALYSIS ID, ANOTHER FUNCTION WILL FETCH THE DATA
def scan_URL(target_URL):
    #The varibale "count" refers to how mnay times the analysis will be attempted to be checked if it is running or its done
    count = 0
    error_check = False
    sent_request = False
    url = "https://www.virustotal.com/api/v3/urls"

    payload = { "url": target_URL }
    headers = {
        "accept": "application/json",
        "x-apikey": "key here",
        "content-type": "application/x-www-form-urlencoded"
    }
#NOTE: WORK ON FIXING THIS THE RESPONSE SENT SHOULD BE CHECKED FOR ERROR THEN IF IT IS ERROR FREE IT SHOULD BE CHECKED UNTIL IT IS COMPLETED USING THE ANALYSIS ID
    while count <= 20:
        if sent_request is False:
            response = requests.post(url, data=payload, headers=headers)
            confirmation = response_analysis(rec_response=response)
            response = response.json()
            analysis_id = response["data"]["id"]

        if response["data"]["attributes"]["status"] == 'queued' or response["data"]["attributes"]["status"] == 'running':
            time.sleep(5)
            continue
        #NOTE: function which aggregates the response will be here

#info1 stores the url which was scanned
def aggregate_virustotal_results_URLSCAN(rec_resonse, info1):
    warning = False

    malicious_count=rec_resonse["data"]["attributes"]["stats"]["malicious"]
    suspicious_count=rec_resonse["data"]["attributes"]["stats"]["suspicious"]
    undetected_count=rec_resonse["data"]["attributes"]["stats"]["undetected"]
    harmless_count=rec_resonse["data"]["attributes"]["stats"]["harmless"]
    timeout_count=rec_resonse["data"]["attributes"]["stats"]["timeout"]
    conf_timeout=rec_resonse["data"]["attributes"]["stats"]["confirmed_timeout"]
    failure_count=rec_resonse["data"]["attributes"]["stats"]["failure"]
    type_unsupported_count=rec_resonse["data"]["attributes"]["stats"]["type_unsupported"]
    total_engines = malicious_count+suspicious_count+undetected_count+harmless_count+timeout_count+conf_timeout+failure_count+type_unsupported_count

    if ((timeout_count+conf_timeout+failure_count+type_unsupported_count)/total_engines) > 0.35:
        warning = True
    formatted_response={
        "target_url":info1,
        "warning": warning,
        "details":{
            "level3":undetected_count+timeout_count+conf_timeout+failure_count+type_unsupported_count,
            "level2":harmless_count,
            "level1":malicious_count+suspicious_count
        }
    }
    return formatted_response
