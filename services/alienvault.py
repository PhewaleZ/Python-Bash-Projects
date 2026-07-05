import requests
import json
from dotenv import load_dotenv
from os import getenv

async def scan_IP_AV() -> tuple:
    ...

def testing_function():
    load_dotenv()
    API_key= getenv("AV_API_KEY")
    header = {"X-OTX-API-KEY": API_key}
    ip = '104.21.56.85'
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"

    response = requests.get(url=url,
                            headers=header,
                            timeout=5)
    
    with open("AV_testing_gen.json", "w") as f:
        json.dump(response.json(), fp=f, indent=4)

    print("DONE")

testing_function()