import json
import os
from dotenv import load_dotenv
from ipaddress import IPv4Address, IPv6Address
from typing import Literal
import asyncio
import httpx


def _ratio(numerator: int, denominator: int) -> float:
    """Return a rounded ratio, treating an empty engine/vote set as zero."""
    if denominator <= 0:
        return 0.0
    return round(numerator / denominator, ndigits=2)


def _response_json(response: httpx.Response | dict) -> dict:
    """Accept both an httpx response and an already-decoded JSON object."""
    if isinstance(response, dict):
        return response
    return response.json()


#This function is what makes the HTTP request and validates it and returns if it is the expected response or an error
async def send_request(url: str, headers: dict, client: httpx.AsyncClient, payload: dict | None = None, is_url: bool = False) -> tuple[bool, str | httpx.Response]:
    last_error = "Unknown"
    for _ in range(4):
        try:
            if is_url is True:
                response = await client.post(
                    url=url, headers=headers, timeout=20, data=payload or {}
                )

            else:
                response = await client.get(
                    url=url, headers=headers, timeout=20
                )

            response.raise_for_status()

        except httpx._exceptions.TimeoutException:
            return (False, "Could not communicate with the VirusTotal API server, TIMEOUT occured.")

        except httpx._exceptions.ConnectError:
            return (False, "Could not connect to the VT API server.")

        #NOTE:In this match case block, the first 3 cases are errors that if occur, there is no point in sending another http request
        except httpx._exceptions.HTTPStatusError as e:
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
                    last_error = f"HTTP {e.response.status_code}: {e.response.reason_phrase}"
                    continue

        except httpx.RequestError as e:

            last_error = f"VirusTotal Error: {str(e)}"
            continue

        else:
            return (True, response)
        
    #If the for loop reaches all 4 iterations and a "non-critical" error has not occured but an error none the less, then the last error is returned along with a bool indicating that an error has occured
    return (False, last_error)
    
#NOTE: The scanning ip address VT endpoint accepts both ipv6 and ipv4 addresses
#The variable scan_type will indicate whether an IP ao domain is being scanned
async def scan_ip_domain_vt(target_ip_domain: IPv4Address | IPv6Address| str, scan_type: Literal["DOMAIN", "IP"], httpxclient: httpx.AsyncClient) -> tuple[bool, str | dict]:
    load_dotenv(override=True)
    API_KEY = os.getenv("VIRUSTOTALAPI_KEY")

    if API_KEY is None:
        return (False, 'Virus Total API key is None')

    if scan_type == 'IP':
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{target_ip_domain}"
    elif scan_type == 'DOMAIN':
        url = f"https://www.virustotal.com/api/v3/domains/{target_ip_domain}"
    else:
        return (False, "scan_type must be 'IP' or 'DOMAIN'")

    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY
    }

    request_check = await send_request(url=url, headers=headers, client=httpxclient)

    if request_check[0] is True:
        assert not isinstance(request_check[1], str)
        virus_total_res = aggregate_vt_results_ip_domain(rec_response=request_check[1], target_name=target_ip_domain) 
        return (True, virus_total_res)
    else:
        return (False, request_check[1]) # pyright: ignore[reportReturnType]

def aggregate_vt_results_ip_domain(rec_response: httpx.Response | dict, target_name: IPv4Address|IPv6Address|str) -> dict:
    warning: list[str] = []

    json_rec_response = _response_json(rec_response)
    last_analysis_stats = json_rec_response.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

    malicious_count=last_analysis_stats.get("malicious", 0)
    suspicious_count=last_analysis_stats.get("suspicious", 0)
    undetected_count=last_analysis_stats.get("undetected", 0)
    harmless_count=last_analysis_stats.get("harmless", 0)
    timeout_count=last_analysis_stats.get("timeout", 0)
    total_engines=malicious_count+suspicious_count+undetected_count+harmless_count+timeout_count
    lvl3_ratio=_ratio(undetected_count, total_engines)
    lvl2_ratio=_ratio(harmless_count, total_engines)
    lvl1_ratio=_ratio(malicious_count+suspicious_count, total_engines)
    if total_engines > 0 and _ratio(timeout_count, total_engines) > 0.35:
        warning.append("Large number of engines queried by VT's API failed to scan")

    formatted_response = {
        'target': str(target_name),
        'warnings': warning,
        'details':{
            "level3":{
                "count":undetected_count,
                "ratio":lvl3_ratio
            },
            "level2":{
                "count":harmless_count,
                "ratio":lvl2_ratio
            },
            "level1":{
                "count":malicious_count+suspicious_count,
                "ratio":lvl1_ratio
            }
        }
    }
    
    return (formatted_response)


async def scan_file_vt(file_hash: str, target_file_name:str, httpxclient: httpx.AsyncClient) -> tuple[bool, str|dict]:
    load_dotenv()

    API_KEY = os.getenv("VIRUSTOTALAPI_KEY")

    if API_KEY == None:
        return (False, 'VirusTotal API key is None')
    
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

    headers = {
        "x-apikey": API_KEY,
        "accept": "application/json"
    }

    request_check = await send_request(url=url, headers=headers, client=httpxclient)

    #NOTE:if the first index is true, then a response.Request was returned, not a string
    if request_check[0] is True:
        assert not isinstance(request_check[1], str)
        virus_total_res = aggregate_vt_results_filehash(rec_response=request_check[1], target_name=target_file_name)
        return(True, virus_total_res) 
    else:
        return (False, request_check[1])  # pyright: ignore[reportReturnType]


def aggregate_vt_results_filehash(rec_response: httpx.Response | dict, target_name: str) -> dict:
    warning: list[str] = []

    json_rec_response = _response_json(rec_response)
    attributes = json_rec_response["data"]["attributes"]
    sigma_stats = attributes.get("sigma_analysis_stats", {})
    last_analysis_stats = attributes.get("last_analysis_stats", {})

    sigma_stats_critical=sigma_stats.get("critical", 0)
    sigma_stats_high=sigma_stats.get("high", 0)
    sigma_stats_medium=sigma_stats.get("medium", 0)
    sigma_stats_low=sigma_stats.get("low", 0)
    total_sigma_stats= sigma_stats_critical+sigma_stats_high+sigma_stats_medium+sigma_stats_low
    if sigma_stats_critical > 0 or (sigma_stats_high+sigma_stats_medium) > total_sigma_stats*0.4:
        warning.append("Strange or abnormal patterns observed in 'sigma statistics'")

    votes = attributes.get("total_votes", {})
    harmless_vote_count=votes.get("harmless", 0)
    malicious_vote_count=votes.get("malicious", 0)
    total_vote_engines=harmless_vote_count+malicious_vote_count
    malicious_vote_ratio=_ratio(malicious_vote_count, total_vote_engines)
    if malicious_vote_ratio >= 0.7:
        vote_verdict = 'HARMFUL'
    elif malicious_vote_ratio >= 0.5:
        vote_verdict = 'CONCERNING'
    elif malicious_vote_ratio >= 0.2:
        vote_verdict = 'OKAY'
    else:
        vote_verdict = 'SAFE'

    malicious_count=last_analysis_stats.get("malicious", 0)
    suspicious_count=last_analysis_stats.get("suspicious", 0)
    undetected_count=last_analysis_stats.get("undetected", 0)
    harmless_count=last_analysis_stats.get("harmless", 0)
    timeout_count=last_analysis_stats.get("timeout", 0)
    conf_timeout=last_analysis_stats.get("confirmed-timeout", last_analysis_stats.get("confirmed_timeout", 0))
    failure_count=last_analysis_stats.get("failure", 0)
    type_unsupported_count=last_analysis_stats.get("type-unsupported", last_analysis_stats.get("type_unsupported", 0))
    total_engines= malicious_count+suspicious_count+undetected_count+harmless_count+timeout_count+conf_timeout+failure_count+type_unsupported_count
    lvl3_ratio=_ratio(undetected_count, total_engines)
    lvl2_ratio=_ratio(harmless_count+int(harmless_vote_count*0.003), total_engines)
    lvl1_ratio=_ratio(malicious_count+suspicious_count+int(malicious_vote_count*0.003), total_engines)
    failed_engine_count = timeout_count+conf_timeout+failure_count+type_unsupported_count
    if total_engines > 0 and _ratio(failed_engine_count, total_engines) > 0.35:
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
                "ratio":lvl3_ratio
            },
            "level2":{
                "count":harmless_count+(int(harmless_vote_count*0.003)),
                "ratio":lvl2_ratio
            },
            "level1":{
                "count":malicious_count+suspicious_count+(int(malicious_vote_count*0.003)),
                "ratio":lvl1_ratio
            }
        }
    }

    return formatted_response

async def scan_url_vt(target_url: str, httpxclient: httpx.AsyncClient):
    load_dotenv()

    API_KEY = os.getenv("VIRUSTOTALAPI_KEY")

    if API_KEY == None:
        return (False, 'Virus Total API key is None')
    
    url = "https://www.virustotal.com/api/v3/urls"

    payload = { "url": target_url }
    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY,
        "content-type": "application/x-www-form-urlencoded"
    }

    request_check = await send_request(url=url, headers=headers, is_url=True, payload=payload, client=httpxclient)

    #NOTE:if the first index is true, then a response.Request was returned, not a string
    if request_check[0] is False:
        return (False, f"The request could not be made to Virustotal's API server, LAST KNOWN STATUS IS:{request_check[1]}")
    
    else:
        assert not isinstance(request_check[1], str)
        ret_result_id = _response_json(request_check[1])
        analysis_id = ret_result_id["data"]["id"]

    last_status = ''
    #This is the part which attempts to retrieve the analysis
    for _ in range(10):
        url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

        headers = {
            "accept": "application/json",
            "x-apikey": API_KEY
        }
        #The request_check tuple is overwritten in this new request
        request_check = await send_request(url=url, headers=headers, is_url=False, client=httpxclient)
        if request_check[0] is False:
            last_status = request_check[1]
            await asyncio.sleep(8)
            continue
        else:
            assert not isinstance(request_check[1], str)
            response = _response_json(request_check[1])

        status = (
            response.get("data", {}).get("attributes", {}).get("status")
        )
        if status == 'queued' or status == 'running':
            last_status = status
            await asyncio.sleep(8)
            continue
        elif status == 'completed':
            virus_total_res = aggregate_vt_results_urlscan(rec_response=response, target_name=target_url)
            return (True, virus_total_res)
        else:
            last_status = status or 'unknown'
            await asyncio.sleep(8)
            continue
    
    return (False, f'The api took too long do return a finished response, LAST KNOWN STATUS IS {last_status}')
    
#info1 stores the url which was scanned
def aggregate_vt_results_urlscan(rec_response: httpx.Response | dict, target_name: str) -> dict:
    warning: list[str] = []
    json_rec_response = _response_json(rec_response)
    stats = json_rec_response.get("data", {}).get("attributes", {}).get("stats", {})

    malicious_count=stats.get("malicious", 0)
    suspicious_count=stats.get("suspicious", 0)
    undetected_count=stats.get("undetected", 0)
    harmless_count=stats.get("harmless", 0)
    timeout_count=stats.get("timeout", 0)
    conf_timeout=stats.get("confirmed_timeout", stats.get("confirmed-timeout", 0))
    failure_count=stats.get("failure", 0)
    type_unsupported_count=stats.get("type_unsupported", stats.get("type-unsupported", 0))
    total_engines = malicious_count+suspicious_count+undetected_count+harmless_count+timeout_count+conf_timeout+failure_count+type_unsupported_count
    lvl3_ratio = _ratio(undetected_count, total_engines)
    lvl2_ratio = _ratio(harmless_count, total_engines)
    lvl1_ratio = _ratio(malicious_count+suspicious_count, total_engines)

    failed_engine_count = timeout_count+conf_timeout+failure_count+type_unsupported_count
    if total_engines > 0 and _ratio(failed_engine_count, total_engines) > 0.35:
        warning.append("Large number of engines queried by VT's API failed to scan")
    formatted_response={
        "target_url":target_name,
        "warnings": warning,
        "details":{
            "level3":{
                "count":undetected_count,
                "ratio":lvl3_ratio
            },
            "level2":{
                "count":harmless_count,
                "ratio":lvl2_ratio
            },
            "level1":{
                "count":malicious_count+suspicious_count,
                "ratio":lvl1_ratio
            }
        }
    }
    return formatted_response


if __name__ == "__main__":
    async def stuff():
            async with asyncio.TaskGroup() as tg:
                async with httpx.AsyncClient() as client:
                    task1 = tg.create_task(scan_ip_domain_vt(IPv4Address("8.8.8.8"), scan_type="IP", httpxclient=client))
                    task2 = tg.create_task(scan_ip_domain_vt(IPv4Address("1.1.1.1"), scan_type="IP", httpxclient=client))

                    result1 = await task1
                    result2 = await task2

            results = [result1, result2]

            print(results, "\n")
            with open("asynctest1.json", "w") as file:
                json.dump(results, fp=file, indent=4 )
            

    asyncio.run(stuff())
