import requests
import json
from dotenv import load_dotenv
from os import getenv

def error_check(rec_response: requests):
    if rec_response.status_code == 200:
        return (True)



def make_request(query_type, detail):
    count = 1
    load_dotenv()
    API_key= getenv("AV_API_KEY")
    header = {"X-OTX-API-KEY": API_key}
    match query_type:
        case "ip4":
            url=f"https://otx.alienvault.com/api/v1/indicators/IPv4/{detail}/general"

    while count <= 4:
        try:
            response = requests.get(url=url,
                                headers=header,
                                timeout=10)
        except requests.exceptions.Timeout:
            ...

async def scan_IP_AV(target_IP: str) -> tuple:
    ...

def testing_function():
    load_dotenv()
    API_key= getenv("AV_API_KEY")
    header = {}
    ip = '1.1.1.1'
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    try:
        response = requests.get(url=url,
                            headers=header,
                            timeout=10)
    except requests.exceptions.Timeout:
        print("TIMEOUT")
        return 1

    with open("AV_testing.json", "w") as f:
        json.dump(response.json(), fp=f, indent=4)

    print("DONE")

testing_function()