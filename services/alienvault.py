import requests
from dotenv import load_dotenv
from os import getenv
from typing import Literal
from  ipaddress import IPv4Address, IPv6Address
import httpx
#NOTE: The parameter "target_detail" holds the actual target of the scan
async def make_get_request(query_type: Literal["IPV4", "IPV6", "DOMAIN", "HOSTNAME", "HASH", "LIGHT_URL"], target_detail: str|IPv6Address|IPv4Address, client: httpx.AsyncClient ) -> tuple[bool, str|httpx.Response]:
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
            response = await client.get(url=url, headers=header, timeout=10)
            response.raise_for_status()

        except httpx.TimeoutException:
            return (False, "Could not communicate with the Alienvault's API server, TIMEOUT occured.")
        
        except httpx.ConnectError:
            return (False, "Could not connect to the Alienvault's API server.")
    
        except httpx.HTTPStatusError as e:
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
                    last_error = f"ALIENVAULT ERROR: HTTP {e.response.status_code}: {e.response.reason_phrase}"
                    continue
    
        except httpx.RequestError as e:
            last_error = f"ALIENVAULT ERROR: {str(e)}" 
            continue

        else:
            return(True, response)
        
    return (False, last_error)


async def scan_file_av(file_hash: str, httpxclient: httpx.AsyncClient) -> tuple[bool, str| dict]:

    result = await make_get_request(query_type="HASH", target_detail=file_hash, client=httpxclient)

    if result[0] is True:
        assert isinstance(result[1], httpx.Response)
        av_result = aggregate_av_results(rec_response=result[1])
        return (True, av_result)
    else:
        assert isinstance(result[1], str)
        return (False, result[1])

async def scan_ip_av(target_ip: IPv4Address| IPv6Address, httpxclient: httpx.AsyncClient) -> tuple:

    if isinstance(target_ip, IPv4Address) is True:
        result = await make_get_request(query_type="IPV4", target_detail=target_ip, client=httpxclient)
    else:
        result = await make_get_request(query_type="IPV6", target_detail=target_ip, client=httpxclient)

    if result[0] is True:
        assert isinstance(result[1], httpx.Response)
        av_result = aggregate_av_results(rec_response=result[1])
        return (True, av_result)
    else:
        assert isinstance(result[1], str)
        return (False, result[1])

async def scan_domain_av(target_domain: str, httpxclient: httpx.AsyncClient) -> tuple[bool, str|dict]:
    result = await make_get_request(query_type="DOMAIN", target_detail=target_domain, client=httpxclient)

    if result[0] is True:
        assert isinstance(result[1], httpx.Response)
        av_result = aggregate_av_results(rec_response=result[1])
        return (True, av_result)
    else:
        assert isinstance(result[1], str)
        return (False, result[1])

def aggregate_av_results(rec_response: httpx.Response) -> dict:
    json_rec_response = rec_response.json()
    details_of_pulses = []
    pulse_info = json_rec_response.get("pulse_info") or {}
    pulses = pulse_info.get("pulses") or []
    pulse_count = pulse_info.get("count")
    if pulse_count is None:
        pulse_count = len(pulses)

    #NOTE: The key "base_indicator" is used to hint if AV actually had the target in its database
    found = bool(json_rec_response.get("base_indicator"))

    for pulse in pulses:
        pulse_id = pulse.get("id")
        pulse_name = pulse.get("name")

        details_of_pulses.append({"name":pulse_name,
                                  "id": pulse_id})
        
    #NOTE: If less than 3 pulses are found then its treated as level 3, as the absence of evidence doesnt mean that the target is clean
    concern_lvl = ""
    match pulse_count:
        case count if count <= 2:
            concern_lvl = "level 3"
        case count if 3 <= count <= 5:
            concern_lvl = "level 2"
        case count if count >= 6:
            concern_lvl = "level 1"

    target_name = json_rec_response.get("indicator")
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

async def make_post_request(target_detail: str, client: httpx.AsyncClient) -> tuple[bool, str|httpx.Response]:
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
            response = await client.post(url=url, headers=header, data=data, timeout=30)
            response.raise_for_status()

        except httpx.TimeoutException:
            return (False, "Couldn't communicate with the Alienvault's API server, TIMEOUT occured.")

        except httpx.ConnectError:
            return (False, "Could not connect to the Alienvault's API server.")

        except httpx.HTTPStatusError as e:
            match e.response.status_code:
                case 403:
                    return (False, "Access denied by Alienvault's API server")
                case 429:
                    return (False, "The rate limit for the Alienvault's API server has been reached")
                case 400 | 401 | 404:
                    return (False, f"The following error has occured with the Alienvault's API query: {str(e)} ")
                case _:
                    last_error = f"ALIENVAULT ERROR: HTTP {e.response.status_code}: {e.response.reason_phrase}"
                    continue

        except httpx.RequestError as e:
            last_error = f"ALIENVAULT ERROR: {str(e)}"
            continue

        else:
            return (True, response)
    
    return (False, last_error)


async def scan_url_av(target_url: str, scan_type: Literal["LIGHT_URL", "HEAVY_URL"], httpxclient: httpx.AsyncClient) -> tuple[bool, str|dict]:

    if scan_type == "LIGHT_URL":
        result_check = await make_get_request(query_type="LIGHT_URL", target_detail=target_url,client=httpxclient)

        if result_check[0] is False:
            assert isinstance(result_check[1], str)
            return (False, result_check[1])
        else:
            assert isinstance(result_check[1], httpx.Response)
            result_json = result_check[1].json()

        if result_json.get("detail", {}) == "endpoint not found":
            return (False, "AV API couldnt find the endpoint")
        else:
            #NOTE:The variable result_json isnt passed on here as it is only used for the above if statement
            AV_result = aggregate_av_results(rec_response=result_check[1])
            return (True, AV_result)

    else:
        result_check = await make_post_request(target_detail=target_url, client=httpxclient)

        if result_check[0] is False:
            assert isinstance(result_check[1], str)
            return (False, result_check[1]) 
        else:
            assert isinstance(result_check[1], httpx.Response)
            result_json = result_check[1].json() 

        #NOTE: The variable is deliberately overwritten
        if result_json.get("status", {}) == "ok":
            link = {"result_link" : "https://otx.alienvault.com/submissions/list"}
            return (True, link)
        else:
            return (False, "The url couldnt be submitted")
    
#NOTE: This function acts as a testing function for catching erros and evaluating Alienvaults's endpoine
def testing_function():
    API_KEY= getenv("AV_API_KEY")
    header = {"X-OTX-API-KEY": API_KEY}
    target=IPv4Address("8.8.8.8")

    url=f"https://otx.alienvault.com/api/v1/indicators/IPv4/{target}/general"

    response = requests.get(url=url, headers=header, timeout=10) # pyright: ignore[reportArgumentType]
    with open("AV_ip_resp_example.json", "w") as f:
            json.dump(response.json(), fp=f, indent=2) # type: ignore
    

if __name__ == "__main__":
    testing_function()