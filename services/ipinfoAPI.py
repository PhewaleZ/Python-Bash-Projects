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

def error_check(rec_response: requests):
    json_rec_response= rec_response

    try:
        if rec_response.status_code in [500, 502, 503, 504, 507, 505, 429]:
            raise NONPermenantERROR

    except NONPermenantERROR:
        sleep(4)
        error="Too many failed attempts"
        return (False, 'NON-CRITICAL', error)
    

async def see_own_ip():
    load_dotenv()
    API_key = getenv("IPINFO_API_KEY")
    
    if API_key is None:
        return (False, 'IPINFO api key is None')

    url = f"https://api.ipinfo.io/lite/me?token={API_key}"

    try:
        response = requests.get(url=url, timeout=10)
    except requests.exceptions.Timeout:
        return (False, "Couldnt communicate with IPINFO server")
    
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

    url= f'https://api.ipinfo.io/lite/me?token=abc'

    response = requests.get(url=url)
    json_response = response.json()

    with open('errtesting.json', 'w') as f:
        json.dump(obj=json_response, fp=f, indent=4)

testing_function()