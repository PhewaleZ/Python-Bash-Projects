import requests
import os
from dotenv import load_dotenv
import json
import time

#NOTE: When a scan is done by virustotal and one of the scanning functions are used, take note that a tuple is returned, the first value in the tuple is going to be a boolean to indicate whether the result was successful
class PermenantERROR(Exception):
    pass
class NONPermenantERROR(Exception):
    pass

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
    

    
async def scan_IP(target_IP):
    count = 1
    load_dotenv()
    api_key = os.getenv("VIRUSTOTALAPI_KEY")

    if api_key == None:
        return (False,)

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{target_IP}"

    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    okay = False
    #NOTE: This part involves the request to virustotal being done over and over again if an error occurs
    #NOTE: confirmation[0] indicates whether or not the received response is okay
    #NOTE: confirmation[1] indicates the type/severity of the error, if critcal then the request is not repeated
    #NOTE: confirmation[2] provides more detail on the error
    while count <= 3:
        response = requests.get(url, headers=headers, timeout=10)
        confirmation = response_error_check(rec_response=response)
        #NOTE: WATCH FOR STRING VALUES AND BE SURE THEY MATCH
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
    virus_total_res = aggregate_virustotal_results_IP(rec_response=response)

    return (True, virus_total_res)

def aggregate_virustotal_results_IP(rec_response, info1):
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
        return False
    
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