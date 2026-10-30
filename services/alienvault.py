import requests
from dotenv import load_dotenv
from os import getenv
from typing import Literal
from  ipaddress import IPv4Address, IPv6Address

#NOTE: The parameter "detail" holds the actual target of the scan
def make_get_request(query_type: Literal["IPV4", "IPV6", "DOMAIN", "HOSTNAME", "HASH", "LIGHT_URL"], target_detail: str|IPv6Address|IPv4Address) -> tuple[bool, str|requests.Response]:
    url = ''
    last_error = ''
    load_dotenv()
    API_KEY= getenv("AV_API_KEY")

    if API_KEY is None:
        return (False, "The alienvault API key is None")
    
    header = {"X-OTX-API-KEY": API_KEY}

    match query_type:
        case "IPV4":
            url=f"https://otx.alienvault.com/api/v1/indicators/IPv4/{target_detail}/general"
        case "IPV6":
            url=f"https://otx.alienvault.com//api/v1/indicators/IPv6/{target_detail}/general"
        case "DOMAIN":
            url=f"https://otx.alienvault.com/api/v1/indicators/domain/{target_detail}/general"
        case "HOSTNAME":
            url=f"https://otx.alienvault.com/api/v1/indicators/hostname/{target_detail}/general"
        case "HASH":
            url=f"https://otx.alienvault.com/api/v1/indicators/file/{target_detail}/general"
        case "LIGHT_URL":
            url=f"https://otx.alienvault.com/api/v1/indicators/url/{target_detail}/general"
    
    for _ in range(4):
        try:
            response = requests.get(url=url, headers=header, timeout=10)
            response.raise_for_status()

        except requests.exceptions.Timeout:
            return (False, "Could not communicate with the Alienvault's API server, TIMEOUT occured.")
        
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
                    last_error = f"ALIENVAULT ERROR: HTTP {e.response.status_code}: {e.response.reason}"
                    continue
    
        except requests.exceptions.RequestException as e:
            assert e.response is not None
            last_error = f"ALIENVAULT ERROR: HTTP code: {e.response.status_code}: {e.response.reason}" 
            continue

        else:
            return(True, response)
        
    return (False, last_error)


def scan_file_AV(file_hash: str) -> tuple[bool, str| dict]:
    result = make_get_request(query_type="HASH", target_detail=file_hash)

    if result[0] is True:
        assert isinstance(result[1], requests.Response)
        av_result = aggregate_AV_results(rec_response=result[1])
        return (True, av_result)
    else:
        assert isinstance(result[1], str)
        return (False, result[1])

def scan_IP_AV(target_ip: IPv4Address| IPv6Address) -> tuple:
    if isinstance(target_ip, IPv4Address) is True:
        result = make_get_request(query_type="IPV4",target_detail=target_ip)
    else:
        result = make_get_request(query_type="IPV6", target_detail=target_ip)

    if result[0] is True:
        assert isinstance(result[1], requests.Response)
        av_result = aggregate_AV_results(rec_response=result[1])
        return (True, av_result)
    else:
        assert isinstance(result[1], str)
        return (False, result[1])

def scan_domain_hostname_AV(target_domain: str) -> tuple[bool, str|dict]:
    result = make_get_request(query_type="DOMAIN", target_detail=target_domain)

    if result[0] is True:
        assert isinstance(result[1], requests.Response)
        av_result = aggregate_AV_results(rec_response=result[1])
        return (True, av_result)
    else:
        assert isinstance(result[1], str)
        return (False, result[1])

def aggregate_AV_results(rec_response: requests.Response) -> dict:
    json_rec_response = rec_response.json()
    details_of_pulses = []
    pulse_count = json_rec_response["pulse_info"]["count"]

    #NOTE: The key "base_indicator" is used to hint if AV actually had the target in its database
    if json_rec_response["base_indicator"] is not None:
        found = True
    else:
        found = False

    pulses = json_rec_response["pulse_info"]["pulses"]

    for pulse in pulses:
        pulse_id= pulse["id"]
        pulse_name= pulse["name"]

        details_of_pulses.append({"name":pulse_name,
                                  "id": pulse_id})
    #NOTE: If less than 3 pulses are found then its treated as level 3, as the absence of evidence doesnt mean that the target is clean
    concern_lvl = ""
    match pulse_count:
        case x if pulse_count <= 2:
            concern_lvl = "level 3"
        case x if 3 <= pulse_count <= 5:
            concern_lvl = "level 2"
        case x if pulse_count >= 6:
            concern_lvl = "level 1"

    target_name = json_rec_response["indicator"]
    formatted_response ={
        "target":target_name,
        "pulse_count":pulse_count,
        "found":found,
        "pulse_details":{
            "pulses":details_of_pulses,
            "concern": concern_lvl
        }
    }

    return (formatted_response)

def make_post_request(target_detail: str) -> tuple[bool, str|requests.Response]:
    last_error = ''
    load_dotenv()
    API_KEY= getenv("AV_API_KEY")
    if API_KEY is None:
        return (False, "Alienvault API key is None")
    
    url=f"https://otx.alienvault.com/api/v1/indicators/submit_url"
    header = {"X-OTX-API-KEY": API_KEY}
    data={
        "url": target_detail
}

    for _ in range(4):
            try:
                response = requests.post(url=url, headers=header, data=data,timeout=30)
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
                        last_error = f"ALIENVAULT ERROR: HTTP {e.response.status_code}: {e.response.reason}"
                        continue
        
            except requests.exceptions.RequestException as e:
                assert e.response is not None
                last_error = f"ALIENVAULT ERROR: HTTP {e.response.status_code}: {e.response.reason}"
                continue
            else:
                return(True, response)
    
    return (False, last_error)


def scan_url_AV(target_url, scan_type: Literal["LIGHT_URL", "HEAVY_URL"]) -> tuple[bool, str|dict]:

    if scan_type == "LIGHT_URL":
        result_check = make_get_request(query_type="LIGHT_URL",target_detail=target_url)

        if result_check[0] is False:
            assert isinstance(result_check[1], str)
            return (False, result_check[1])
        else:
            assert isinstance(result_check[1], requests.Response)
            result_json = result_check[1].json()

        if result_json.get("detail", {}) == "endpoint not found":
            return (False, "AV API couldnt find the endpoint")
        else:
            AV_result = aggregate_AV_results(rec_response=result_json)
            return (True, AV_result)

    else:
        result_check = make_post_request(target_detail=target_url)

        if result_check[0] is False:
            assert isinstance(result_check[1], str)
            return (False, result_check[1]) 
        else:
            assert isinstance(result_check[1], requests.Response)
            result_json = result_check[1].json() 

        #NOTE: The variable is deliberately overwritten
        if result_json.get("status", {}) == "ok": #type: ignore
            link = {"result_link" : "https://otx.alienvault.com/submissions/list"}
            return (True, link)
        else:
            return (False, "The url couldnt be submitted")
    

def testing_function():
    result = scan_domain_hostname_AV(target_domain="gmail.com")
    #if result[0] is True:
        #with open("AV_Domain_resp_example.json", "w") as f:
        #    json.dump(result[1], fp=f, indent=2) # type: ignore
    #else:
        #print(f"An error has occured: {result[1]}")
    

if __name__ == "__main__":
    testing_function()