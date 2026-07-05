from dotenv import load_dotenv
from os import getenv
import requests
import json

#NOTE: error checking for an invalid IP address will be done way earlier into the api
def make_request(API_key: str, is_own_ip: bool, target_ip='0.0.0.0') -> tuple:

    if is_own_ip is False:
        url = f"https://api.ipinfo.io/lite/{target_ip}?token={API_key}"

    if is_own_ip is True:
        url = f"https://api.ipinfo.io/lite/me?token={API_key}"

    while count <= 4:
        try:
            response = requests.get(url=url, timeout=8)
        except requests.exceptions.Timeout:
            return (False, "Couldnt communicate with IPINFO server")
        
        if response.status_code != 200:
            error = error_check(rec_response=response)

            #IF the IPINFO api key is invalid then there is no point in continuing the loop
            if error == 'Unknown token':
                return (False, error)
            
            count += 1
            continue
        else:
            return (True, response)
        
    return (False, error)

#This function will collect the actual error
def error_check(rec_response: requests) -> str:
    json_rec_response= rec_response.json()

    err_message= json_rec_response.get("error", {}).get("title", {})

    return err_message

async def see_own_ip() -> tuple:
    count = 1
    load_dotenv()
    API_key = getenv("IPINFO_API_KEY")
    
    if API_key is None:
        return (False, 'IPINFO api key is None')
    
    response = make_request(API_key=API_key, is_own_ip=True)

    if response[0] is False:
        return (False, response[1])
    
    if response[0] is True:
        ipinfo_results = aggregate_results(details=response[1])
        return (True, ipinfo_results)
    
def aggregate_results(details) -> dict:
    ipinfo_details={
        "IP Adress": details["ip"],
        "asn_code": details["asn_code"],
        "as_name": details["as_name"],
        "as_domain": details["as_domain"],
        "country": details["country"],
    }

    return ipinfo_details

async def check_ip(target_ip: str) -> tuple:
    load_dotenv()
    API_key = getenv("IPINFO_API_KEY")
    
    if API_key is None:
        return (False, 'IPINFO api key is None')
    
    response = make_request(API_key=API_key, is_own_ip=True, target_ip=target_ip)

    if response[0] is False:
        return (False, response[1])
    
    if response[0] is True:
        ipinfo_results = aggregate_results(details=response[1])
        return (True, ipinfo_results)


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

testing_function()