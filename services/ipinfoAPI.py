from dotenv import load_dotenv
from os import getenv
import requests
import json
from ipaddress import IPv4Address, IPv6Address


def make_request(API_KEY: str, is_own_ip: bool, target_ip: IPv4Address|IPv6Address) -> tuple[bool, str|requests.Response]:
    last_error = ''
    url = ''
    if is_own_ip is False:
        url = f"https://api.ipinfo.io/lite/{target_ip}?token={API_KEY}"

    if is_own_ip is True:
        url = f"https://api.ipinfo.io/lite/me?token={API_KEY}"

    for _ in range(4):
        try:
            response = requests.get(url=url, timeout=8)
            response.raise_for_status()
        except requests.exceptions.Timeout:
            return (False, "Could not communicate with the IPINFO server, TIMEOUT occured.")
        
        except requests.exceptions.ConnectionError:
            return (False, "Could not connect to the IPINFO API server.")
        
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
                    last_error = f"IPINFO ERROR: HTTP {e.response.status_code}: {e.response.reason}"
                    continue
        
        except requests.exceptions.RequestException as e:
            assert e.response is not None
            last_error = f"IPINFOR ERROR: HTTP code {e.response.status_code}: {e.response.reason}" 
            continue
        else:
            return (True, response)
            
    return (False, last_error)
    
def aggregate_results(rec_response: requests.Response) -> dict:
    json_rec_response = rec_response.json()
    
    ipinfo_results={
        "IP Address": json_rec_response["ip"],
        "asn_code": json_rec_response["asn"],
        "as_name": json_rec_response["as_name"],
        "as_domain": json_rec_response["as_domain"],
        "country": json_rec_response["country"],
    }
    return ipinfo_results

def Ipinfoscan(target_ip: IPv4Address| IPv6Address) -> tuple[bool, str| dict ]:
    load_dotenv()
    API_KEY = getenv("IPINFO_API_KEY")
    
    if API_KEY is None:
        return (False, 'IPINFO api key is None')
    
    response_check = make_request(API_KEY=API_KEY, is_own_ip=False, target_ip=target_ip)

    if response_check[0] is True:
        assert not isinstance(response_check[1], str)
        ipinfo_results = aggregate_results(rec_response=response_check[1])
        return (True, ipinfo_results)
    else:
        assert isinstance(response_check[1], str)
        return (False, response_check[1])


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

if __name__ == "__main__":
    testing_function()