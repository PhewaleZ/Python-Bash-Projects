import requests
import json
from dotenv import load_dotenv
from os import getenv
from time import sleep

def error_check(rec_response: requests):
    if rec_response.status_code == 200:
        return (True, "OK")
    
    match rec_response.status_code:
        case 400:
            return (False, "The request sent to Alienvault API server is invalid")
        case 401:
            return (False, "Authentication failed with the Alienvault API server")
        case 403:
            return (False, "Alienvault API didnt grant permission for the made request")
        case 404:
            return (False, "The resource doesnt exist")
        case 429:
            sleep(15)
            return (False, "Alienvault throttled the request")
        case 500:
            return (False, "An error has occured on Alienvault's side")
        case _:
            return (False, "An unexpected error has occured")


#The variable "detail" just holds any relevant information to make the request to the API server
def make_request(query_type, detail):
    count = 1
    load_dotenv()
    API_key= getenv("AV_API_KEY")
    if API_key is None:
        return (False, "The alienvault API key is None")
    
    header = {"X-OTX-API-KEY": API_key}

    match query_type:
        case "ip4":
            url=f"https://otx.alienvault.com/api/v1/indicators/IPv4/{detail}/general"
        case "ip6":
            url=f"https://otx.alienvault.com//api/v1/indicators/IPv6/{detail}/general"
        case "domain":
            url=f"https://otx.alienvault.com/api/v1/indicators/domain/{detail}/general"
        case "light_url":
            url=f"https://otx.alienvault.com/api/v1/indicators/url/{detail}/general"
            #NOTE: work on this url scan thing, This heavy_url scan involves the user having to se the results on the url:https://otx.alienvault.com/submissions/list
        case "heavy_url":
            url=f"https://otx.alienvault.com/api/v1/indicators/url/{detail}/general"

    while count <= 4:
        try:
            response = requests.get(url=url,
                                headers=header,
                                timeout=10)
            confirmation = error_check(rec_response=response)

            if confirmation[0] is True:
                return (True, response)
            
            if confirmation[0] is False:
                last_err = confirmation[1]
                count += 1
                continue
        except requests.exceptions.Timeout:
            last_err = "Couldnt communicate with Alienvault's API server"
            count += 1
            continue

    return (False, last_err)

def make_post_request(target: str) -> tuple:
    url=f"https://otx.alienvault.com/api/v1/indicators/url/{target}/general"
def scan_IP_AV(target_IP: str, IP_type: str) -> tuple:
    ...

def scan_domain_AV(target_domain: str) -> tuple:
    ...

def scan_url_AV(target_url: str, scan_type: str) -> tuple:
    ...

def testing_function():
    load_dotenv()
    API_key= getenv("AV_API_KEY")
    header = {"X-OTX-API-KEY": API_key}
    target_url="https://hianime.city/"
    data={
        "url": target_url
}
    url=f"https://otx.alienvault.com/api/v1/indicators/submit_url"
    try:
        response = requests.post(url=url,
                            headers=header,
                            data=data,
                            timeout=10)
    except requests.exceptions.Timeout:
        print("TIMEOUT")
        return 1

    with open("AV_testing.json", "w") as f:
        json.dump(response.json(), fp=f, indent=4)

    print("DONE")

def testing_ret_id(id):
    ...

testing_function()