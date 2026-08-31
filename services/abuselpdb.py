import requests
import json
from time import sleep
from os import getenv
from dotenv import load_dotenv
from ipaddress import IPv4Address, IPv6Address

#The report_age parameter is used to determine how old the reports retrieved by abuselpdb API can, at max, be
def scan_ip_APDB(target_IP: IPv6Address| IPv4Address, report_age: int) -> tuple:
    last_error = ''
    load_dotenv()
    API_key=getenv("ABUSELPDB_API_KEY")

    if API_key is None:
        return (False, "The abuselpdb API key is None")

    url = 'https://api.abuseipdb.com/api/v2/check'

    if report_age == 0:
        report_age = 90

    querystring = {
        'ipAddress': target_IP,
        'maxAgeInDays': report_age,
            }

    headers = {
    'Accept': 'application/json',
    'Key': API_key
        }

    for _ in range(4):
                try:
                    response = requests.post(url=url, headers=headers,timeout=10, params=querystring)
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


def aggregate_APDB_results(rec_response) -> dict:
    concern = ''
    rec_response = rec_response.json()
    data = rec_response["data"]
    abpdb_score = data["abuseConfidenceScore"]

    match abpdb_score:
        case x if 0<=abpdb_score<20:
            concern = "level 3"
        case x if 20<=abpdb_score<60:
            concern = "level 2"
        case x if 60<=abpdb_score:
            concern = "level 1"

    
    formatted_response = {
        "target_name": data["ipAddress"],
        "is_whitelist": data["isWhitelisted"],
        "is_tor":data["isTor"],
        "country_of_origin": data["countryCode"],
        "is_whitelisted":data["isWhitelisted"],
        "domain":data["domain"],
        "concern":{
            "abusel_score": data["abuseConfidenceScore"],
            "concern_value":concern
        },
        "isp_details":{
            "isp_name":data["isp"],
            "isp_type":data["usageType"]
        },
        "report_details":{
            "report_count":data["totalReports"],
            "reports":data.get("reports", None)
            }
    }

    return formatted_response

def testing_function():
    load_dotenv()
    API_key=getenv("ABUSELPDB_API_KEY")
    url = 'https://api.abuseipdb.com/api/v2/check'

    target = "197.249.236.235"
    querystring = {
    'ipAddress': target,
    'maxAgeInDays': '90'
        }

    headers = {
    'Accept': 'application/json',
    'Key': API_key
        }
    print(f"The key is {API_key}")
    try:
        response = requests.request(method='GET', url=url, headers=headers, params=querystring)
        print(response)
        print("linebreak here")
        print(f"The status code is: {response.status_code}")
    except requests.exceptions.Timeout:
        print("timeout")
        return 1

    decodedResponse = json.loads(response.text)
    with open ("abpdb.json", "w") as file:
        json.dump(obj=decodedResponse, fp=file, indent=4)

    print("DONE")
    return 0
testing_function()