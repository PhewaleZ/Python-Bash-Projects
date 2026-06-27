from dotenv import load_dotenv
import ipinfo
from os import getenv

async def see_own_ip():
    load_dotenv()
    API_key = getenv("IPINFO_API_KEY")
    handler = ipinfo.getHandlerLite(API_key)

    details = handler.getDetails()
    dict_details=details.all

    ipinfo_results=aggregate_results(details=dict_details)
    return ipinfo_results

def aggregate_results(details):
    own_details={
        "IP Adress": details["ip"],
        "asn_code": details["asn_code"],
        "as_name": details["as_name"],
        "as_domain": details["as_domain"],
        "country": details["country"],
        "continent": details["continent"]["name"]
    }

    return own_details