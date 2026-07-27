from dotenv import load_dotenv
from os import getenv
import requests
import json

#NOTE: error checking for an invalid IP address will be done way earlier into the api
def make_request(API_key: str, is_own_ip: bool, target_ip='0.0.0.0') -> tuple[bool, str|dict]:
    last_error = ''
    url = ''
    if is_own_ip is False:
        url = f"https://api.ipinfo.io/lite/{target_ip}?token={API_key}"

    if is_own_ip is True:
        url = f"https://api.ipinfo.io/lite/me?token={API_key}"

    for _ in range(4):
        try:
            response = requests.get(url=url, timeout=8)
            response.raise_for_status()
        except requests.exceptions.Timeout:
            return (False, "Couldn't communicate with the IPINFO server, TIMEOUT occured.")
        
        except requests.exceptions.ConnectionError:
            return (False, "Could not connect to the IPINFO API server.")
        
        #In this match case block, the first 2 cases are errors that if occur, there is no point in sending another request
        except requests.exceptions.HTTPError as e:
            if e.response is None:
                return (False, str(e))
            match e.response.status_code:
                case 403:
                    return (False, "Access denied by IPINFO server")
                case 429:
                    #NOTE: The ipinfo API endpoint is the free tier and it offers unlimited requests.
                    return (False, "The IPINFO server has throttled this request")
                case 400 | 401 | 404:
                    return (False, f"The following error has occured with the IPINFO API query: {str(e)} ")
                case _:
                    last_error = f"HTTP {e.response.status_code}: {e.response.reason}"
                    continue
        
        except requests.exceptions.RequestException as e:
            last_error = f"HTTP code: {e.response.status_code}: {e.response.reason}" #type: ignore as this error will never occur in normal circumstances
            continue
        else:
            results = aggregate_results(details=response)
            return (True, results)
            
    return (False, last_error)

def see_own_ip() -> tuple[bool, str|dict]:
    count = 1
    load_dotenv()
    API_key = getenv("IPINFO_API_KEY")
    
    if API_key is None:
        return (False, 'IPINFO api key is None')
    
    response = make_request(API_key=API_key, is_own_ip=True)

    if response[0] is True:
        return (True, response[1])
    else:
        return (False, response[1])


def aggregate_results(details) -> dict:
    details = details.json()

    ipinfo_details={
        "IP Adress": details["ip"],
        "asn_code": details["asn_code"],
        "as_name": details["as_name"],
        "as_domain": details["as_domain"],
        "country": details["country"],
    }

    return ipinfo_details

def check_ip(target_ip: str) -> tuple[bool, str| dict ]:
    load_dotenv()
    API_key = getenv("IPINFO_API_KEY")
    
    if API_key is None:
        return (False, 'IPINFO api key is None')
    
    response = make_request(API_key=API_key, is_own_ip=True, target_ip=target_ip)
    
    if response[0] is True:
        ipinfo_results = aggregate_results(details=response[1])
        return (True, ipinfo_results)
    else:
        return (False, response[1])


#NOTE: This function acts as a testing function for what type of errors ipinfo's api returns as finding documentation from ipinfo direrctly was hard
def testing_function():
    load_dotenv()
    API_key = getenv("IPINFO_API_KEY")

    url= f'https://api.ipinfo.io/lite/87.120.104.69?token={API_key}'

    try:
        response = requests.get(url=url, timeout=10)
    except:
        print("ERROR HAS OCCURED")
        return 1
    
    json_response = response.json()

    with open('errtesting.json', 'w') as f:
        json.dump(obj=json_response, fp=f, indent=4)
