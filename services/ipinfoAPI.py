from dotenv import load_dotenv
import ipinfo
from os import getenv
import requests



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