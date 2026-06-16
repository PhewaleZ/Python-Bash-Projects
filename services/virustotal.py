import requests
import os
from dotenv import load_dotenv
import json
import time
class PermenantERROR(Exception):
    pass
class NONPermenantERROR(Exception):
    pass

async def scan_IP(target_IP):
    count = 1
    load_dotenv()
    api_key = os.getenv("VIRUSTOTALAPI_KEY")

    if api_key == None:
        return False

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
        if confirmation[0] == False and confirmation[1] == 'NON-Crititcal':
            count +=1
            last_error=confirmation[2]

        if confirmation[0] == False and confirmation[1] == 'Critical':
            #This will eject out of this and starts the process of returning an error to the user
            return (False, confirmation[2])
        
        if confirmation[0] == True:
            okay = True
    #This part also catches an error
    if okay == False:
        return (False, last_error)
    
    #If no errors are caught then the results are aggregated
    aggregate_virustotal_results(scan_type='IP', rec_response=response)

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
        return (False, 'Critical', error)
    except NONPermenantERROR:
        time.sleep(4)
        error="Too many failed attempts"
        return (False, 'NON-Crititcal', error)
    else:
        return (True,'',error)

#Info1 will hold the ip address
def aggregate_virustotal_results(scan_type, rec_response, info1):
    #this calculates the total number of engines whihc virustotal queried
    total_engines = rec_response["data"]["attributes"]["last_analysis_stats"]["malicious"]+rec_response["data"]["attributes"]["last_analysis_stats"]["suspicious"]+rec_response["data"]["attributes"]["last_analysis_stats"]["undetected"]+rec_response["data"]["attributes"]["last_analysis_stats"]["harmless"]+rec_response["data"]["attributes"]["last_analysis_stats"]["timeout"]
    warning= False
    #NOTE: HERE WORK ON ADDING A FEATURE TO INFORM OF ABNORMAL RESULTS SUCH AS A LARGE NUMBER OF TIMEOUTS
    if (rec_response["data"]["attributes"]["last_analysis_stats"]["timeout"] > (0.3 * total_engines)):
        warning = True
    formatted_response = {
        'target IP': info1,
        'country': rec_response["data"]["attributes"]["country"],
        'details':{
            "level2":rec_response["data"]["attributes"]["last_analysis_stats"]["harmless"]+rec_response["data"]["attributes"]["last_analysis_stats"]["undetected"],
            "level1":rec_response["data"]["attributes"]["last_analysis_stats"]['suspicious'] +rec_response["data"]["attributes"]["last_analysis_stats"]["malicious"] # type: ignore
        } # type: ignore
    }
    
    #NOTE: ADD FUNCTION WHICH PUTS THE DATA INTO THE DATABASE HERE

async def scan_file(file):
    ... 
    