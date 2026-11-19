import json
from time import sleep
from os import getenv
from dotenv import load_dotenv
from ipaddress import IPv4Address, IPv6Address
import httpx
import asyncio

#The report_age parameter is used to determine how old the reports retrieved by abuselpdb API can, at max, be
async def scan_ip_apdb(target_ip: IPv6Address| IPv4Address, httpxclient: httpx.AsyncClient,report_age=90, ) -> tuple[bool, str|dict]:
    last_error = ''
    load_dotenv()
    API_KEY=getenv("ABUSELPDB_API_KEY")

    if API_KEY is None:
        return (False, "The abuselpdb API key is None")

    url = 'https://api.abuseipdb.com/api/v2/check'

    querystring = {
        'ipAddress': target_ip,
        'maxAgeInDays': report_age,
            }

    headers = {
    'Accept': 'application/json',
    'Key': API_KEY
        }

    for _ in range(4):
                try:
                    response = await httpxclient.get(url=url, headers=headers, timeout=10, params=querystring)
                    response.raise_for_status()

                except httpx.TimeoutException:
                    return (False, "Couldn't communicate with the Abuselpdb's API server, TIMEOUT occured.")
                
                except httpx.ConnectError:
                    return (False, "Could not connect to the Abuselpdb's API server.")
            
                except httpx.HTTPStatusError as e:
                    if e.response is None:
                        return (False, str(e))
                    match e.response.status_code:
                        case 403:
                            return (False, "Access denied by Abuselpdb's API server")
                        case 429:
                            return (False, "Abuselpdb has throttled the request")
                        case 400 | 401 | 404:
                            return (False, f"The following error has occured with the Abuselpdb API query: {str(e)} ")
                        case _:
                            last_error = f"ABUSELPDB ERROR: HTTP {e.response.status_code}: {e.response.reason_phrase}"
                            sleep(5)
                            continue
            
                except httpx.RequestError as e:
                    last_error = f"ABUSELPDB ERROR: {str(e)}"
                    sleep(5)
                    continue
        
                else:

                    return(True, aggregate_apdb_results(rec_response=response))
 
    return (False, last_error)


def aggregate_apdb_results(rec_response: httpx.Response) -> dict:
    json_rec_response= rec_response.json()
    
    data = json_rec_response.get("data") or {}
    abpdb_score = data.get("abuseConfidenceScore")
    concern = None

    if abpdb_score is not None:
        match abpdb_score:
            case x if 0 <= x < 20:
                concern = "level 3"
            case x if 20 <= x < 60:
                concern = "level 2"
            case x if 60 <= x:
                concern = "level 1"

    
    formatted_response = {
        "target_name": data.get("ipAddress"),
        "is_whitelist": data.get("isWhitelisted"),
        "is_tor": data.get("isTor"),
        "country_of_origin": data.get("countryCode"),
        "is_whitelisted": data.get("isWhitelisted"),
        "domain": data.get("domain"),
        "concern":{
            "abusel_score": abpdb_score,
            "concern_value":concern
        },
        "isp_details":{
            "isp_name": data.get("isp"),
            "isp_type": data.get("usageType")
        },
        "report_details":{
            "report_count": data.get("totalReports"),
            "reports": data.get("reports")
            }
    }

    return formatted_response

#This function is for testing purposes only
if __name__ == "__main__":
    async def stuff():
            async with asyncio.TaskGroup() as tg:
                async with httpx.AsyncClient() as client:
                    task1 = tg.create_task(scan_ip_apdb(target_ip=IPv4Address("8.8.8.8"), httpxclient=client, report_age=90))
                    task2 = tg.create_task(scan_ip_apdb(target_ip=IPv4Address("1.1.1.1"), httpxclient=client, report_age=90))

                    result1 = await task1
                    result2 = await task2

            results = [result1, result2]

            print(results, "\n")
            with open("asynctest1.json", "w") as file:
                json.dump(results, fp=file, indent=4 )
            

    asyncio.run(stuff())