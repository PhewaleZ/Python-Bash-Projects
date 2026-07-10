import requests
import json
from dotenv import load_dotenv
from os import getenv
from time import sleep

def error_check(rec_response: requests):
    if rec_response.status_code == 200:
        return (True, "OK")
    
    match rec_response.status_code:
        case 400:
            return (False, "The request sent to Alienvault API server is invalid")
        case 401:
            return (False, "Authentication failed with the Alienvault API server")
        case 403:
            return (False, "Alienvault API didnt grant permission for the made request")
        case 404:
            return (False, "The resource doesnt exist in Alienvault's API")
        case 429:
            sleep(15)
            return (False, "Alienvault throttled the request")
        case 500:
            return (False, "An error has occured on Alienvault's side")
        case _:
            return (False, "An unexpected error has occured with the Alienvault request")


#The variable "detail" just holds any relevant information to make the request to the API server
def make_request(query_type, detail):
    count = 1
    load_dotenv()
    API_key= getenv("AV_API_KEY")
    if API_key is None:
        return (False, "The alienvault API key is None")
    
    header = {"X-OTX-API-KEY": API_key}

    match query_type:
        case "ipv4":
            url=f"https://otx.alienvault.com/api/v1/indicators/IPv4/{detail}/general"
        case "ipv6":
            url=f"https://otx.alienvault.com//api/v1/indicators/IPv6/{detail}/general"
        case "domain":
            url=f"https://otx.alienvault.com/api/v1/indicators/domain/{detail}/general"
        case "hostname":
            url=f"https://otx.alienvault.com/api/v1/indicators/hostname/{detail}/general"
        case "hash":
            url=f"https://otx.alienvault.com/api/v1/indicators/file/{detail}/general"
        case "light_url":
            url=f"https://otx.alienvault.com/api/v1/indicators/url/{detail}/general"
            #NOTE: work on this url scan thing, This heavy_url scan involves the user having to se the results on the url:https://otx.alienvault.com/submissions/list
            #NOTE: The api should return the json indicating if it was successfully submitted
        case "heavy_url":
            url=f"https://otx.alienvault.com/api/v1/indicators/url/{detail}/general"

    while count <= 4:
        try:
            response = requests.get(url=url,
                                headers=header,
                                timeout=10)
            confirmation = error_check(rec_response=response)

            if confirmation[0] is True:
                return (True, response)
            
            if confirmation[0] is False:
                last_err = confirmation[1]
                count += 1
                continue
        except requests.exceptions.Timeout:
            last_err = "Couldnt communicate with Alienvault's API server"
            count += 1
            continue

    return (False, last_err)

def make_post_request(target: str) -> tuple:
    url=f"https://otx.alienvault.com/api/v1/indicators/url/{target}/general"


def scan_file(file_detail: str, is_hash: bool) -> bool:
    if is_hash is True:
        result = make_request(query_type="hash", detail=file_detail)

    if is_hash is False:
        return (False, "This functionality isnt present yet")

    if result[0] is False:
        return (False, result[1])
    
    result_json= result.json()

    AV_result_file = aggregate_IP_Domain_Hostname_hash_results_AV(rec_response=result_json)

    return (True, AV_result_file)


def scan_IP_AV(target_IP: str, is_ipv4: bool) -> tuple:
    if is_ipv4 is True:
        result = make_request(query_type="ipv4",detail=target_IP)
    
    if is_ipv4 is False:
        result = make_request(query_type="ipv6", detail=target_IP)

    if result[0] is False:
        return (False, result[1])
    
    result_json= result.json()

    AV_result_IP = aggregate_IP_Domain_Hostname_hash_results_AV(rec_response=result_json)

    return (True, AV_result_IP)



def scan_domain_hostname_AV(target_domain: str) -> tuple:
    result = make_request(query_type="domain", detail=target_domain)

    if result[0] is False:
        return (False, result[1])
    
    result_json= result.json()

    AV_result_Domain = aggregate_IP_Domain_Hostname_hash_results_AV(rec_response=result_json)

    return (True, AV_result_Domain)

def aggregate_IP_Domain_Hostname_hash_results_AV(rec_response: dict) -> dict:
    pulse_count = rec_response["pulse_info"]["count"]

    #This part will be done if the number of pulss are greater than 0
    if pulse_count >= 1:
        details_of_pulses = []
        pulses=rec_response["pulse_info"]["pulses"]

        for pulse in pulses:
            pulse_id=pulse["id"]
            pulse_name=pulse["name"]

            details_of_pulses.append({"name":pulse_name,
                                      "id": pulse_id})
        #If less than 3 pulses are found then its treated as level 3 as the absence of evidence doesnt mean that the target is clean
        match pulse_count:
            case x if pulse_count <= 2:
                concern = "level 3"
            case x if 3 <= pulse_count <= 5:
                concern = "level 2"
            case x if pulse_count >= 6:
                concern = "level 1"

        formatted_response ={
            "pulse_count":pulse_count,
            "pulse_details":{
                "pulses":details_of_pulses,
                "concern": concern
            }
        }
        
        #NOTE: insert function which writes to the database here
        #NOTE: facilitate the checking of the full response should be done for this API

        return (formatted_response)
    
    #If the number of pulses are 0 then the following dictionary is returned instead
    formatted_response = {
        "pulse_count": 0,
        "pulse_details":{
            "pulses":None,
            "concern": None
        }
    }

    return (formatted_response)



def scan_url_AV(target_url: str, is_lightscan: bool) -> tuple:
    if is_lightscan is True:
        result = make_request(query_type="light_url",detail=target_url)
    
    if is_lightscan is False:
        result = make_request(query_type="heavy_url", detail=target_url)

    if result[0] is False:
        return (False, result[1])
    
    result_json= result.json()

    if result_json.get("detail", {}) == "endpoint not found":
        return (False, "AV API couldnt find the endpoint")
    
    #NOTE: continue here by adding the function to aggregate the result, and verify the json returned by the API when the url is scanned in a sandbox mode

    

def testing_function():
    load_dotenv()
    API_key= getenv("AV_API_KEY")
    header = {"X-OTX-API-KEY": API_key}
    target="https://wvdme.com/afu.php?zoneid=11215377&var=11215377&rid=VNWXKjLGtzaM7cA1lFMN6A%3D%3D&rhd=true&ab2r=0&sf=1&os=windows&os_version=19.0.0&is_mobile=false&browser_version=150.0.7871.114"
    data={
        "url": target
}
    url=f"https://otx.alienvault.com/api/v1/indicators/url/{target}/general"
    try:
        response = requests.get(url=url,
                            headers=header,
                            timeout=10)
    except requests.exceptions.Timeout:
        print("TIMEOUT")
        return 1
    except requests.exceptions.JSONDecodeError:
        print("couldnt decode json")
        return 1
    with open("errtesting.json", "w") as f:
        json.dump(response.json(), fp=f, indent=4)

    print("DONE")

testing_function()