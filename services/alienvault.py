import requests
import json
from dotenv import load_dotenv
from os import getenv
from typing import Literal
from  ipaddress import IPv4Address, IPv6Address
#The variable "detail" just holds any relevant information to make the request to the API server
def make_get_request(query_type: Literal["IPV4", "IPV6", "DOMAIN", "HOSTNAME", "HASH", "LIGHT_URL"], detail: str|IPv6Address|IPv4Address) -> tuple[bool, str|requests.Response]:
    url = ''
    last_error = ''
    load_dotenv()
    API_key= getenv("AV_API_KEY")

    if API_key is None:
        return (False, "The alienvault API key is None")
    
    header = {"X-OTX-API-KEY": API_key}

    match query_type:
        case "IPV4":
            url=f"https://otx.alienvault.com/api/v1/indicators/IPv4/{detail}/general"
        case "IPV6":
            url=f"https://otx.alienvault.com//api/v1/indicators/IPv6/{detail}/general"
        case "DOMAIN":
            url=f"https://otx.alienvault.com/api/v1/indicators/domain/{detail}/general"
        case "HOSTNAME":
            url=f"https://otx.alienvault.com/api/v1/indicators/hostname/{detail}/general"
        case "HASH":
            url=f"https://otx.alienvault.com/api/v1/indicators/file/{detail}/general"
        case "LIGHT_URL":
            url=f"https://otx.alienvault.com/api/v1/indicators/url/{detail}/general"
    
    for _ in range(4):
        try:
            response = requests.get(url=url, headers=header, timeout=10)
            response.raise_for_status()

        except requests.exceptions.Timeout:
            return (False, "Couldn't communicate with the Alienvault's API server, TIMEOUT occured.")
        
        except requests.exceptions.ConnectionError:
            return (False, "Could not connect to the Alienvault's API server.")
    
        except requests.exceptions.HTTPError as e:
            if e.response is None:
                return (False, str(e))
            match e.response.status_code:
                case 403:
                    return (False, "Access denied by Alienvault's API server")
                case 429:
                    return (False, "The rate limit for the Alienvault's API server has been reached")
                case 400 | 401 | 404:
                    return (False, f"The following error has occured with the Alienvault's API query: {str(e)} ")
                case _:
                    last_error = f"HTTP {e.response.status_code}: {e.response.reason}"
                    continue
    
        except requests.exceptions.RequestException as e:
            last_error = f"HTTP code: {e.response.status_code}: {e.response.reason}" #type: ignore as this error will never occur in normal circumstances
            continue

        else:
            return(True, response)
        
    return (False, last_error)


def scan_file_AV(file_hash: str, is_hash=True) -> tuple[bool, str| dict]:
    if is_hash is True:
        result = make_get_request(query_type="HASH", detail=file_hash)
    else:
        return (False, "This functionality isnt present yet")

    if result[0] is False:
        return (False, result[1]) #type: ignore
    else:
        result_json= result[1].json() #type: ignore

    AV_result_file = aggregate_AV_results(rec_response=result_json)

    return (True, AV_result_file)


def scan_IP_AV(target_IP: IPv4Address| IPv6Address) -> tuple:
    if isinstance(target_IP, IPv4Address) is True:
        result = make_get_request(query_type="IPV4",detail=target_IP)
    else:
        result = make_get_request(query_type="IPV6", detail=target_IP)

    if result[0] is False:
        return (False, result[1])
    else:
        result_json = result[1].json() #type: ignore

    AV_result_IP = aggregate_AV_results(rec_response=result_json)

    return (True, AV_result_IP)



def scan_domain_hostname_AV(target_domain: str) -> tuple[bool, str|dict]:
    result = make_get_request(query_type="DOMAIN", detail=target_domain)

    if result[0] is False:
        return (False, result[1]) #type: ignore
    else:
        result_json= result[1].json()#type: ignore

    AV_result_Domain = aggregate_AV_results(rec_response=result_json)

    return (True, AV_result_Domain)

def aggregate_AV_results(rec_response: dict) -> dict:
    concern = ''
    pulse_count = rec_response["pulse_info"]["count"]
    if rec_response["base_indicator"] is not None:
        found = True
    else:
        found = False
    target_name = rec_response["indicator"]
    #This part will be done if the number of pulses are greater than 0
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

        #The found key is used to indicate if the AV API actually had an entry for the result, its not a guarantee just an extra piece of info
        formatted_response ={
            "target":target_name,
            "pulse_count":pulse_count,
            "found":found,
            "pulse_details":{
                "pulses":details_of_pulses,
                "concern": concern
            }
        }
        
        #NOTE: insert function which writes to the database here
        #NOTE: facilitate the checking of the full response from the database should be done for this API

        return (formatted_response)
    
    #If the number of pulses are 0 then the following dictionary is returned instead
    formatted_response = {
        "target":target_name,
        "pulse_count":0,
        "found":found,
        "pulse_details":{
            "pulses":None,
            "concern": None
        }
    }

    return (formatted_response)

def make_post_request(detail: str) -> tuple[bool, str|requests.Response]:
    last_error = ''
    load_dotenv()
    API_key= getenv("AV_API_KEY")
    if API_key is None:
        return (False, "Alienvault API key is None")
    
    url=f"https://otx.alienvault.com/api/v1/indicators/submit_url"
    header = {"X-OTX-API-KEY": API_key}
    data={
        "url": detail
}

    for _ in range(4):
            try:
                response = requests.post(url=url, headers=header, data=data,timeout=10)
                response.raise_for_status()

            except requests.exceptions.Timeout:
                return (False, "Couldn't communicate with the Alienvault's API server, TIMEOUT occured.")
            
            except requests.exceptions.ConnectionError:
                return (False, "Could not connect to the Alienvault's API server.")
        
            except requests.exceptions.HTTPError as e:
                if e.response is None:
                    return (False, str(e))
                match e.response.status_code:
                    case 403:
                        return (False, "Access denied by Alienvault's API server")
                    case 429:
                        return (False, "The rate limit for the Alienvault's API server has been reached")
                    case 400 | 401 | 404:
                        return (False, f"The following error has occured with the Alienvault's API query: {str(e)} ")
                    case _:
                        last_error = f"HTTP {e.response.status_code}: {e.response.reason}"
                        continue
        
            except requests.exceptions.RequestException as e:
                last_error = f"HTTP code: {e.response.status_code}: {e.response.reason}" #type: ignore as this error will never occur in normal circumstances
                continue
    
            else:
                return(True, response)
    
    return (False, last_error)


def scan_url_AV(target_url: str, scan_type: Literal["LIGHT_URL", "HEAVY_URL"]) -> tuple:

    if scan_type == "LIGHT_URL":
        result = make_get_request(query_type="LIGHT_URL",detail=target_url)

        if result[0] is False:
            return (False, result[1])
        else:
            result_json = result[1].json() #type: ignore

        if result_json.get("detail", {}) == "endpoint not found":
            return (False, "AV API couldnt find the endpoint")

        AV_result_url = aggregate_AV_results(rec_response=result_json)
        
        return (True, AV_result_url)


        #This is done if the scan being conducted on the URL is complex
    else:
        result = make_post_request(detail=target_url)

        if result[0] is False:
            return (False, result[1])
        else:
            result_json = result[1]
        #If the field of status is "okay" then it means that it as ben successfully submitted to the API server and the link to it is returned
        if result_json.get("status", {}) == "okay": #type: ignore
            link = {"result_link" : "https://otx.alienvault.com/submissions/list"}
            return (True, link)
        else:
            return (False, "The url couldnt be submitted")
    

def testing_function():
    load_dotenv()
    API_key= getenv("AV_API_KEY")
    header = {"X-OTX-API-KEY": API_key}
    target="https://hianime.ms/watch-gachiakuta-episode-8-u68b6"
    data={
        "url": target
}
    url=f"https://otx.alienvault.com/api/v1/indicators/submit_url"
    try:
        response = requests.get(url=url,
                            headers=header,#type: ignore
                            data=data,
                            timeout=10)
        print(f"The status code is: {response.status_code}")
    except requests.exceptions.Timeout:
        print("TIMEOUT")
        return 1
    except requests.exceptions.JSONDecodeError:
        print("couldnt decode json")
        return 1
    with open("errtesting2.json", "w") as f:
        json.dump(response.json(), fp=f, indent=4)

    print("DONE")

if __name__ == "__main__":
    testing_function()