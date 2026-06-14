import requests
import os
from dotenv import load_dotenv
import json
async def scan_IP(target_IP):
    load_dotenv()
    api_key = os.getenv("VIRUSTOTALAPI_KEY")

    if api_key == None:
        return False

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{target_IP}"

    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    response = requests.get(url, headers=headers)

    aggregate_virustotal_results(scan_type='IP', rec_response=response)

#Info1 will hold the ip address
def aggregate_virustotal_results(scan_type, rec_response, info1):
    rec_response = rec_response.json()
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

    