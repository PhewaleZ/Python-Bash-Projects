from dotenv import load_dotenv
import ipinfo
from os import getenv
import requests
from time import sleep
import json

class PermenantERROR(Exception):
    pass
class NONPermenantERROR(Exception):
    pass

#NOTE: error checking for an invalid IP address will be done way earlier into the api
def error_check(rec_response: requests):
    json_rec_response= rec_response.json()

    err_message= json_rec_response.get("error", {}).get("title", {})

    if err_message == "Unknown token":
        return (False, "IPINFO Api key is invalid")

    return (False, err_message)

async def see_own_ip():
    count = 1
    load_dotenv()
    API_key = getenv("IPINFO_API_KEY")
    
    if API_key is None:
        return (False, 'IPINFO api key is None')

    url = f"https://api.ipinfo.io/lite/me?token={API_key}"

    while count <= 4:
        try:
            response = requests.get(url=url, timeout=10)
        except requests.exceptions.Timeout:
            return (False, "Couldnt communicate with IPINFO server")
        
        if response.status_code != 200:
            check = error_check(rec_response=response)

            #IF the IPINFO api key is invalid then there is no point in continuing the loop
            if check[1] == 'IPINFO Api key is invalid':
                return (False, check[1])
            
            count += 1
            continue
        else:
            ...
            #NOTE: this part here should be the part where the results are aggregated and returned to the user

    #NOTE: Insert error checking function here

    return (True, ipinfo_results)

def aggregate_results(details):
    ipinfo_details={
        "IP Adress": details["ip"],
        "asn_code": details["asn_code"],
        "as_name": details["as_name"],
        "as_domain": details["as_domain"],
        "country": details["country"],
        "continent": details["continent"]["name"]
    }

    return ipinfo_details

async def check_ip(target_ip):
    load_dotenv()
    API_key = getenv("IPINFO_API_KEY")
    
    if API_key is None:
        return (False, 'IPINFO api key is None')

    handler = ipinfo.getHandlerLite(API_key)

    details = handler.getDetails(ip_address=target_ip)

    dict_details=details.all

    ipinfo_results=aggregate_results(details=dict_details)

    return (True, ipinfo_results)

def testing_function():
    load_dotenv()
    API_key = getenv("IPINFO_API_KEY")

    url= f'https://api.ipinfo.io/lite/102.123.0.1?token=abc'

    try:
        response = requests.get(url=url, timeout=10)
    except:
        print("ERROR HAS OCCURED")
        return 1
    
    json_response = response.json()

    with open('errtesting.json', 'w') as f:
        json.dump(obj=json_response, fp=f, indent=4)

testing_function()